import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseQuerySource, type TaskReleaseTransaction, type ValidatedTaskReleaseRecord } from './task-release.js';
import type { TaskMode } from './task-catalog.js';
import type { CancellationExecutor } from './run-service.js';
import { readSuccessorPreparationPolicySnapshot } from './run-service.js';
import { finalizeKnownRankedTask, finalizeKnownTrainingTask } from './task-run-completion.js';
import { evaluateTaskRubric, type EvaluateTaskInput, type TaskEvaluationResult } from './task-evaluator.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import { finalizeFencedTaskActionReceipts } from './task-action-fence-finalization.js';
import type { TaskActionEvidenceSink } from './bef-task-executor.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const EVIDENCE_PATH = /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;

export type PreparationStatus = 'preparing' | 'unknown' | 'ready' | 'fenced';
export type PreparationUnknownReason = 'adapter_outcome_unknown' | 'adapter_call_failed' |
  'restart_reconciliation_required' | 'run_state_changed_before_preparation_completed' | 'preparation_identity_mismatch' |
  'baseline_state_mismatch';

export interface TaskPreparationIntentPins {
  preparationId: string;
  runId: string;
  taskIndex: number;
  claimId: string;
  leaseId: string;
  environmentId: string;
  releaseIdentity: string;
  manifestHash: string;
  taskId: string;
  caseId: string;
  caseHash: string;
  initialStateSha256: string;
  executionIdentityHash: string;
  environmentManifestSha256: string;
  applicationSourceHash: string;
  createdAt: string;
}

export interface TaskPreparationObservation {
  revision: number;
  status: PreparationStatus;
  generationId: string | null;
  participantId: string | null;
  payerAddress: string | null;
  baselineStateSha256: string | null;
  fixtureEvidence: EvidenceReference | null;
  baselineEvidence: EvidenceReference | null;
  reasonCode: PreparationUnknownReason | null;
  createdAt: string;
}

export interface TaskPreparationRecord {
  intent: TaskPreparationIntentPins;
  observation: TaskPreparationObservation;
  leaseStatus: 'leased' | 'fenced';
  dispatchStatus: 'dispatching' | 'completed' | 'unknown' | null;
}

export interface TaskPreparationDependencies {
  db: OwnerDatabase;
  releaseSource: TaskReleaseQuerySource;
  preparationAdapter: TaskPreparationAdapter;
  /** Internal allowlisted selector. It receives the sealed case so a future real adapter can match facilitator/payee constraints. */
  environmentSelector: {
    selectEnvironment(input: { runId: string; taskIndex: number; manifestHash: string; environmentManifestSha256: string; taskCase: TaskCase }): Promise<string>;
  };
}

export interface TaskPreparationTarget { runId: string; taskIndex: number; claimId: string }

export interface SuccessorTaskPreparationDependencies extends TaskPreparationDependencies {
  /** Revalidates the original predecessor's sealed evidence before creating a successor intent. */
  predecessorEvidenceSource: TaskEvaluationEvidenceSource;
}

export type TaskPreparationTransaction = Transaction;
export type CanonicalKnownTaskEvaluation = TaskEvaluationResult & {
  status: 'known'; outcome: 'passed' | 'partial' | 'failed'; credit: NonNullable<TaskEvaluationResult['credit']>; unknownReasons: [];
};
export type CanonicalKnownTrainingEvaluation = CanonicalKnownTaskEvaluation;
export type CanonicalKnownRankedEvaluation = CanonicalKnownTaskEvaluation;

/** Internal start boundary. A configured port is authoritative and does not use global readiness. */
export interface PreparedTaskStartPort {
  readCandidatePreparationId(target: TaskPreparationTarget): Promise<string | null>;
  assertReadyInTransaction(tx: TaskPreparationTransaction, target: TaskPreparationTarget, preparationId: string,
    minimumValidUntil: string): Promise<TaskPreparationRecord>;
  hasUsableStartSession(preparation: TaskPreparationRecord, minimumValidUntil: string): boolean;
  /** Optional coordinator singleton proof, checked again before the start transaction commits. */
  assertLeaseHeld?(): Promise<void>;
  /** Called only after the durable start and public execution binding commit. */
  attachStartedSession(preparation: TaskPreparationRecord, minimumValidUntil: string): Promise<void>;
}

/** Output from a trusted internal executor/baseline adapter; never accepted from an agent route. */
export interface TrustedTaskPreparationResult {
  environmentId: string;
  generationId: string;
  manifestHash: string;
  applicationSourceHash: string;
  environmentManifestSha256: string;
  initialStateSha256: string;
  participantId?: string;
  payerAddress?: string;
  fixtureEvidence: EvidenceReference;
  baselineEvidence: EvidenceReference;
}

export interface ConfirmedTaskEnvironmentFence {
  confirmed: true;
  preparationId: string;
  leaseId: string;
  environmentId: string;
  generationId: string | null;
  evidence: EvidenceReference;
}

export type TaskPreparationAdapterOutcome =
  | { status: 'prepared'; result: TrustedTaskPreparationResult }
  | { status: 'unknown'; generationId?: string | null; reasonCode: PreparationUnknownReason };

/**
 * Internal-only executor boundary. Implementations must make prepare idempotent by preparationId,
 * reconcile only the supplied original generation, verify baseline/raw-reference hashes, and confirm
 * a fence before returning. A fence is keyed by preparation identity and must prevent any in-flight
 * or later prepare for that identity from creating a generation, including when generationId is null;
 * checking only a known generation is insufficient. This repository currently has no production
 * implementation of this port.
 */
export interface TaskPreparationAdapter {
  prepare(input: { intent: TaskPreparationIntentPins; dispatchId: string }): Promise<TaskPreparationAdapterOutcome>;
  reconcile(input: { intent: TaskPreparationIntentPins; generationId: string }): Promise<TaskPreparationAdapterOutcome>;
  fence(input: { intent: TaskPreparationIntentPins; generationId: string | null }): Promise<ConfirmedTaskEnvironmentFence>;
  /** Secret-free RAM readiness check; strict start requires the original session to cover the task deadline. */
  hasUsableStartSession?(intent: TaskPreparationIntentPins, minimumValidUntil: string): boolean;
  /** Remove adapter-local credentials after its preparation identity is fenced. */
  clearCredentials?(preparationId?: string): void;
}

// AICODE-NOTE: A synthetic/test adapter may exercise the persistence contract, but no server or run-start path may treat it as executor readiness.

interface RunRow {
  id: string; owner_id: string; agent_id: string; mode: TaskMode; status: string; task_ids: string[];
  release_identity: string; manifest_hash: string; access_generation: number; agent_policy_revision: number;
  queue_live: boolean; overall_live: boolean;
  overall_deadline: Date | string | null;
  successor_preparation_policy_version: string | null;
  successor_preparation_timeout_seconds: number | null;
}
interface IntentRow {
  preparation_id: string; run_id: string; task_index: number; claim_id: string; lease_id: string; environment_id: string;
  release_identity: string; manifest_hash: string; task_id: string; case_id: string; case_hash: string;
  initial_state_sha256: string; execution_identity_hash: string; environment_manifest_sha256: string;
  application_source_hash: string; created_at: Date | string;
}
interface ObservationRow {
  revision: number; status: PreparationStatus; generation_id: string | null; participant_id: string | null;
  payer_address: string | null; baseline_state_sha256: string | null; fixture_evidence: unknown; baseline_evidence: unknown;
  reason_code: PreparationUnknownReason | null; created_at: Date | string;
}
interface LeaseRow { state: 'leased' | 'fenced'; fence_evidence: unknown }

function fail(status: number, code: string, message: string): never { throw new HttpError(status, code, message); }
function validateTarget(target: TaskPreparationTarget): void {
  if (!UUID.test(target.runId) || !UUID.test(target.claimId) || !Number.isSafeInteger(target.taskIndex) ||
      target.taskIndex < 0 || target.taskIndex > 11) {
    fail(400, 'INVALID_TASK_PREPARATION_TARGET', 'A run, claim, and bounded task index are required');
  }
}
function normalizeTarget(target: TaskPreparationTarget): TaskPreparationTarget {
  validateTarget(target);
  return { runId: target.runId.toLowerCase(), taskIndex: target.taskIndex, claimId: target.claimId.toLowerCase() };
}
function validEnvironmentId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
}
function parseEvidence(value: unknown): EvidenceReference | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const ref = value as Record<string, unknown>;
  const sha256 = typeof ref.sha256 === 'string' ? ref.sha256 : '';
  if (typeof ref.path !== 'string' || ref.path.trim() !== ref.path || !EVIDENCE_PATH.test(ref.path) ||
      sha256.length !== 64 || !HASH.test(sha256) ||
      ref.boundary !== 'actual_tool_http_x402_local_evm_application_store') return null;
  return { path: ref.path, sha256: sha256.toLowerCase(), boundary: ref.boundary };
}
function asJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return null; }
}
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
function object(value: unknown): Record<string, unknown> | null {
  const parsed = asJson(value);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
}
/**
 * Internal successor guard: reconstruct the immutable evaluation from its persisted input before
 * treating it as known. A mandatory violation is an allowed terminal failure only when the
 * evaluator itself reproduces the exact failed, zero-credit result and observation-backed claim.
 */
function readKnownCanonicalTaskEvaluation(
  resultValue: unknown,
  inputValue: unknown,
  taskId: string,
  runId: string,
  mode: TaskMode,
): CanonicalKnownTaskEvaluation | null {
  const result = object(resultValue);
  const input = object(inputValue);
  const taskCase = object(input?.taskCase);
  const release = object(input?.release);
  const run = object(input?.run);
  const observations = object(input?.observations);
  const binding = object(observations?.binding);
  if (!result || !input || !taskCase || !release || !run || !observations || !binding ||
      result.taskId !== taskId || result.status !== 'known' ||
      !['passed', 'partial', 'failed'].includes(String(result.outcome)) ||
      !Array.isArray(result.unknownReasons) || result.unknownReasons.length !== 0 ||
      taskCase.taskId !== taskId || taskCase.mode !== mode || run.runId !== runId || run.taskId !== taskId ||
      release.releaseIdentity !== run.releaseIdentity || release.manifestHash !== run.manifestHash ||
      taskCase.caseId !== run.caseId || taskCase.caseHash !== run.caseHash || taskCase.rubricHash !== run.rubricHash) return null;
  for (const key of ['ownerId', 'agentId', 'runId', 'environmentId', 'releaseIdentity', 'manifestHash',
    'caseId', 'caseHash', 'rubricHash', 'taskId']) {
    if (binding[key] !== run[key]) return null;
  }
  const violation = result.mandatoryViolation;
  if (violation !== null) {
    const claim = object(violation);
    if (!claim || typeof claim.rule !== 'string' || claim.rule.length === 0 || !Array.isArray(claim.observationIds) ||
        claim.observationIds.length === 0 || claim.observationIds.some((id) => typeof id !== 'string' || id.length === 0) ||
        new Set(claim.observationIds).size !== claim.observationIds.length || result.outcome !== 'failed' ||
        object(result.credit)?.numerator !== '0') return null;
  }
  try {
    const reconstructed = evaluateTaskRubric(inputValue as EvaluateTaskInput);
    if (reconstructed.status !== 'known' || reconstructed.outcome !== result.outcome ||
        (reconstructed.mandatoryViolation === null) !== (violation === null) ||
        canonicalTaskJson(reconstructed) !== canonicalTaskJson(result)) return null;
    if (reconstructed.mandatoryViolation !== null && (reconstructed.outcome !== 'failed' ||
        reconstructed.credit?.numerator !== '0' || reconstructed.mandatoryViolation.observationIds.length === 0)) return null;
    return reconstructed as CanonicalKnownTaskEvaluation;
  } catch {
    return null;
  }
}
export function readKnownCanonicalTrainingEvaluation(
  resultValue: unknown, inputValue: unknown, taskId: string, runId: string,
): CanonicalKnownTrainingEvaluation | null {
  return readKnownCanonicalTaskEvaluation(resultValue, inputValue, taskId, runId, 'training');
}
export function readKnownCanonicalRankedEvaluation(
  resultValue: unknown, inputValue: unknown, taskId: string, runId: string,
): CanonicalKnownRankedEvaluation | null {
  return readKnownCanonicalTaskEvaluation(resultValue, inputValue, taskId, runId, 'ranked');
}
function readKnownCanonicalEvaluationForMode(
  resultValue: unknown, inputValue: unknown, taskId: string, runId: string, mode: TaskMode,
): CanonicalKnownTaskEvaluation | null {
  return mode === 'training'
    ? readKnownCanonicalTrainingEvaluation(resultValue, inputValue, taskId, runId)
    : readKnownCanonicalRankedEvaluation(resultValue, inputValue, taskId, runId);
}
function validDate(value: unknown): Date | null {
  const parsed = value instanceof Date ? new Date(value.getTime()) : typeof value === 'string' ? new Date(value) : null;
  return parsed && Number.isFinite(parsed.getTime()) ? parsed : null;
}
function isoDate(value: unknown): string | null { return validDate(value)?.toISOString() ?? null; }
function hash(value: unknown): value is string { return typeof value === 'string' && HASH.test(value); }
async function databaseNow(tx: Transaction): Promise<Date> {
  const rows = await tx.execute(sql`SELECT clock_timestamp() AS now`) as unknown as Array<{ now: Date | string }>;
  const now = validDate(rows[0]?.now);
  if (!now) throw new Error('PostgreSQL did not return a successor preparation timestamp');
  return now;
}
function assertSuccessorPreparationWindow(run: RunRow, predecessorFinishedAt: unknown, now: Date): void {
  const policy = readSuccessorPreparationPolicySnapshot(
    run.successor_preparation_policy_version, run.successor_preparation_timeout_seconds,
  );
  const predecessorFinished = validDate(predecessorFinishedAt);
  const overallDeadline = validDate(run.overall_deadline);
  if (!policy) fail(409, 'SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE', 'The run has no supported immutable successor-preparation policy snapshot');
  // AICODE-NOTE: The predecessor must finish before the original run deadline, but preparation time is excluded and may cross it.
  if (!predecessorFinished || !overallDeadline || predecessorFinished.getTime() >= overallDeadline.getTime() ||
      now.getTime() < predecessorFinished.getTime() || now.getTime() - predecessorFinished.getTime() > policy.timeoutSeconds * 1000) {
    fail(409, 'SUCCESSOR_PREPARATION_WINDOW_EXPIRED', 'The successor preparation is outside the pinned database-time window');
  }
}
function rowToIntent(row: IntentRow): TaskPreparationIntentPins {
  return {
    preparationId: row.preparation_id, runId: row.run_id, taskIndex: row.task_index, claimId: row.claim_id,
    leaseId: row.lease_id, environmentId: row.environment_id, releaseIdentity: row.release_identity,
    manifestHash: row.manifest_hash, taskId: row.task_id, caseId: row.case_id, caseHash: row.case_hash,
    initialStateSha256: row.initial_state_sha256, executionIdentityHash: row.execution_identity_hash,
    environmentManifestSha256: row.environment_manifest_sha256, applicationSourceHash: row.application_source_hash,
    createdAt: new Date(row.created_at).toISOString(),
  };
}
function rowToObservation(row: ObservationRow): TaskPreparationObservation {
  return {
    revision: row.revision, status: row.status, generationId: row.generation_id,
    participantId: row.participant_id, payerAddress: row.payer_address,
    baselineStateSha256: row.baseline_state_sha256,
    fixtureEvidence: parseEvidence(asJson(row.fixture_evidence)), baselineEvidence: parseEvidence(asJson(row.baseline_evidence)),
    reasonCode: row.reason_code, createdAt: new Date(row.created_at).toISOString(),
  };
}
function samePins(actual: TaskPreparationIntentPins, expected: Omit<TaskPreparationIntentPins, 'preparationId' | 'leaseId' | 'createdAt' | 'environmentId'>): boolean {
  return actual.runId === expected.runId && actual.taskIndex === expected.taskIndex && actual.claimId === expected.claimId &&
    actual.releaseIdentity === expected.releaseIdentity && actual.manifestHash === expected.manifestHash && actual.taskId === expected.taskId &&
    actual.caseId === expected.caseId && actual.caseHash === expected.caseHash && actual.initialStateSha256 === expected.initialStateSha256 &&
    actual.executionIdentityHash === expected.executionIdentityHash && actual.environmentManifestSha256 === expected.environmentManifestSha256 &&
    actual.applicationSourceHash === expected.applicationSourceHash;
}

function derivePins(release: ValidatedTaskReleaseRecord, run: RunRow, target: TaskPreparationTarget) {
  if (release.releaseIdentity !== run.release_identity || release.manifestHash.toLowerCase() !== run.manifest_hash.toLowerCase()) {
    fail(409, 'TASK_PREPARATION_RELEASE_MISMATCH', 'The sealed release does not match the run release pin');
  }
  const taskId = run.task_ids[target.taskIndex];
  const taskCase = release.manifest.cases[run.mode].find((entry) => entry.taskId === taskId);
  if (!taskId || !taskCase || taskCase.mode !== run.mode || taskCase.executionIdentityHash !== release.manifest.executionIdentityHash) {
    fail(409, 'TASK_PREPARATION_CASE_UNAVAILABLE', 'The exact task case is not present in the validated sealed release');
  }
  return {
    runId: run.id, taskIndex: target.taskIndex, claimId: target.claimId.toLowerCase(), releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash.toLowerCase(), taskId, caseId: taskCase.caseId, caseHash: taskCase.caseHash.toLowerCase(),
    initialStateSha256: taskCase.initialState.stateSha256.toLowerCase(),
    executionIdentityHash: taskCase.executionIdentityHash.toLowerCase(),
    environmentManifestSha256: release.manifest.executionIdentity.environmentManifestSha256.toLowerCase(),
    applicationSourceHash: release.manifest.executionIdentity.x402ServiceSha256.toLowerCase(),
  };
}

type LockedTaskRow = {
  task_index: number; task_id: string; status: string; closure_status: string; closure_id: string | null;
  closure_operation_id: string | null; closure_payload_hash: string | null; closure_reason: string | null;
  action_cutoff_sequence: string | number | null; reconciled_action_sequence: string | number;
  started_at: Date | string | null; finished_at: Date | string | null;
};

async function assertKnownPredecessorProof(tx: Transaction, run: RunRow, targetIndex: number,
  tasks: readonly LockedTaskRow[]): Promise<Date> {
  if (targetIndex < 1 || tasks.length !== run.task_ids.length || tasks.length <= targetIndex ||
      tasks.some((task, index) => task.task_index !== index || task.task_id !== run.task_ids[index])) {
    fail(409, 'RUN_TASK_SET_INCOMPLETE', 'The successor task list does not match the admitted run order');
  }
  for (let index = 0; index < targetIndex; index += 1) {
    const prior = tasks[index]!;
    if ((prior.status !== 'completed' && prior.status !== 'failed') || prior.closure_status !== 'closed' ||
        !prior.closure_id || prior.action_cutoff_sequence === null ||
        BigInt(String(prior.reconciled_action_sequence)) < BigInt(String(prior.action_cutoff_sequence)) || !validDate(prior.finished_at)) {
      fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'Every preceding task must have a known reconciled terminal outcome');
    }
  }
  for (let index = targetIndex; index < tasks.length; index += 1) {
    const current = tasks[index]!;
    if (current.status !== 'queued' || current.started_at !== null || current.finished_at !== null || current.closure_status !== 'open') {
      fail(409, 'RUN_TASK_ORDER_CONFLICT', 'The successor must be the next queued task with only queued successors after it');
    }
  }

  const evaluations = await tx.execute(sql`SELECT task_index,task_id,input_hash,result_hash,input_json,result_json
    FROM oid_run_task_evaluation WHERE run_id=${run.id} AND task_index<${targetIndex} ORDER BY task_index FOR UPDATE`) as unknown as
      Array<{ task_index: number; task_id: string; input_hash: string; result_hash: string; input_json: unknown; result_json: unknown }>;
  if (evaluations.length !== targetIndex) fail(409, 'RUN_EVALUATIONS_INCOMPLETE', 'Every preceding task requires an immutable known evaluation');
  for (let index = 0; index < targetIndex; index += 1) {
    const evaluation = evaluations[index]!;
    const result = readKnownCanonicalEvaluationForMode(evaluation.result_json, evaluation.input_json,
      tasks[index]!.task_id, run.id, run.mode);
    if (evaluation.task_index !== index || evaluation.task_id !== tasks[index]!.task_id || !hash(evaluation.input_hash) || !hash(evaluation.result_hash) ||
        sha256CanonicalTaskJson(asJson(evaluation.input_json)) !== evaluation.input_hash ||
        sha256CanonicalTaskJson(asJson(evaluation.result_json)) !== evaluation.result_hash || !result || result.taskId !== tasks[index]!.task_id ||
        result.status !== 'known' ||
        (result.outcome === 'failed') !== (tasks[index]!.status === 'failed')) {
      fail(409, 'RUN_TASK_EVALUATIONS_UNKNOWN', 'A preceding task evaluation is missing, unknown, or contradictory');
    }
  }

  const predecessorIndex = targetIndex - 1;
  const predecessor = tasks[predecessorIndex]!;
  const evaluationRows = await tx.execute(sql`SELECT run_id,task_index,closure_id,task_id,release_identity,manifest_hash,
      case_hash,rubric_hash,input_hash,result_hash,input_json,result_json
    FROM oid_run_task_evaluation WHERE run_id=${run.id} AND task_index=${predecessorIndex} FOR KEY SHARE`) as unknown as Array<{
      run_id: string; task_index: number; closure_id: string; task_id: string; release_identity: string; manifest_hash: string;
      case_hash: string; rubric_hash: string; input_hash: string; result_hash: string; input_json: unknown; result_json: unknown;
    }>;
  const evaluation = evaluationRows[0];
  const result = evaluation ? readKnownCanonicalEvaluationForMode(evaluation.result_json, evaluation.input_json,
    predecessor.task_id, run.id, run.mode) : null;
  const evaluationInput = asJson(evaluation?.input_json);
  const evaluationInputObject = object(evaluationInput);
  const evaluationTaskCase = object(evaluationInputObject?.taskCase);
  if (!evaluation || evaluation.run_id !== run.id || evaluation.task_index !== predecessorIndex || evaluation.closure_id !== predecessor.closure_id ||
      evaluation.task_id !== predecessor.task_id || evaluation.release_identity !== run.release_identity || evaluation.manifest_hash !== run.manifest_hash ||
      !hash(evaluation.input_hash) || !hash(evaluation.result_hash) || sha256CanonicalTaskJson(evaluationInput) !== evaluation.input_hash ||
      sha256CanonicalTaskJson(asJson(evaluation.result_json)) !== evaluation.result_hash || !result || result.taskId !== predecessor.task_id || result.status !== 'known' ||
      (result.outcome === 'failed') !== (predecessor.status === 'failed')) {
    fail(409, 'RUN_TASK_PREDECESSOR_NOT_KNOWN', 'The immediate predecessor has no exact known evaluation');
  }

  const bundleRows = await tx.execute(sql`SELECT run_id,task_index,owner_id,agent_id,closure_id,closure_operation_id,closure_payload_hash,
      closure_reason,task_id,release_identity,release_manifest_hash,case_id,case_hash,rubric_hash,environment_id,preparation_id,lease_id,
      generation_id,environment_manifest_hash,application_source_hash,execution_identity_hash,initial_state_sha256,bundle_hash,bundle_json
    FROM oid_run_task_observation_bundle WHERE run_id=${run.id} AND task_index=${predecessorIndex} FOR KEY SHARE`) as unknown as Array<{
      run_id: string; task_index: number; owner_id: string; agent_id: string; closure_id: string; closure_operation_id: string | null;
      closure_payload_hash: string; closure_reason: string; task_id: string; release_identity: string; release_manifest_hash: string;
      case_id: string; case_hash: string; rubric_hash: string; environment_id: string; preparation_id: string; lease_id: string;
      generation_id: string; environment_manifest_hash: string; application_source_hash: string; execution_identity_hash: string;
      initial_state_sha256: string; bundle_hash: string; bundle_json: unknown;
    }>;
  const bundleRow = bundleRows[0];
  const bundle = object(bundleRow?.bundle_json);
  const binding = object(bundle?.binding), closure = object(bundle?.closure), execution = object(bundle?.execution);
  if (!bundleRow || !bundle || !binding || !closure || !execution || bundleRow.run_id !== run.id || bundleRow.task_index !== predecessorIndex ||
      bundleRow.owner_id !== run.owner_id || bundleRow.agent_id !== run.agent_id || bundleRow.closure_id !== predecessor.closure_id ||
      bundleRow.closure_operation_id !== predecessor.closure_operation_id || bundleRow.closure_payload_hash !== predecessor.closure_payload_hash ||
      bundleRow.closure_reason !== predecessor.closure_reason || bundleRow.task_id !== predecessor.task_id ||
      bundleRow.release_identity !== run.release_identity || bundleRow.release_manifest_hash !== run.manifest_hash ||
      !hash(bundleRow.bundle_hash) || sha256CanonicalTaskJson(bundle) !== bundleRow.bundle_hash ||
      binding.ownerId !== run.owner_id || binding.agentId !== run.agent_id || binding.runId !== run.id ||
      binding.releaseIdentity !== run.release_identity || binding.manifestHash !== run.manifest_hash || binding.taskId !== predecessor.task_id ||
      binding.environmentId !== bundleRow.environment_id || binding.caseId !== bundleRow.case_id ||
      binding.caseHash !== bundleRow.case_hash || binding.rubricHash !== bundleRow.rubric_hash ||
      evaluation.case_hash !== bundleRow.case_hash || evaluation.rubric_hash !== bundleRow.rubric_hash ||
      evaluationTaskCase?.caseId !== bundleRow.case_id || evaluationTaskCase.caseHash !== bundleRow.case_hash ||
      evaluationTaskCase.rubricHash !== bundleRow.rubric_hash ||
      closure.closureId !== predecessor.closure_id || closure.operationId !== predecessor.closure_operation_id ||
      closure.payloadHash !== predecessor.closure_payload_hash || closure.reason !== predecessor.closure_reason ||
      BigInt(String(closure.actionCutoffSequence)) !== BigInt(String(predecessor.action_cutoff_sequence)) ||
      BigInt(String(closure.reconciledActionSequence)) !== BigInt(String(predecessor.reconciled_action_sequence)) ||
      execution.preparationId !== bundleRow.preparation_id || execution.leaseId !== bundleRow.lease_id ||
      execution.generationId !== bundleRow.generation_id || execution.environmentManifestHash !== bundleRow.environment_manifest_hash ||
      execution.applicationSourceHash !== bundleRow.application_source_hash || execution.executionIdentityHash !== bundleRow.execution_identity_hash ||
      execution.initialStateSha256 !== bundleRow.initial_state_sha256) {
    fail(409, 'RUN_TASK_PREDECESSOR_BUNDLE_MISMATCH', 'The predecessor observation bundle is missing or contradictory');
  }

  const prepRows = await tx.execute(sql`SELECT i.preparation_id,i.run_id,i.task_index,i.lease_id,i.environment_id,i.release_identity,i.manifest_hash,
      i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,
      l.state AS lease_state,l.fence_evidence,o.status AS preparation_status,o.generation_id,o.baseline_state_sha256,
      o.fixture_evidence,o.baseline_evidence,g.generation_id AS registered_generation_id,g.environment_id AS registered_environment_id,
      eb.env_id AS binding_environment_id,eb.generation_id AS binding_generation_id,eb.manifest_hash AS binding_manifest_hash,
      eb.application_source_hash AS binding_application_source_hash
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    LEFT JOIN oid_task_preparation_generation g ON g.preparation_id=i.preparation_id
    LEFT JOIN oid_task_execution_binding eb ON eb.run_id=i.run_id AND eb.task_index=i.task_index
    WHERE i.run_id=${run.id} AND i.task_index=${predecessorIndex} FOR KEY SHARE OF i,l`) as unknown as Array<{
      preparation_id: string; run_id: string; task_index: number; lease_id: string; environment_id: string; release_identity: string;
      manifest_hash: string; task_id: string; case_id: string; case_hash: string; initial_state_sha256: string;
      execution_identity_hash: string; environment_manifest_sha256: string; application_source_hash: string; lease_state: string;
      fence_evidence: unknown; preparation_status: string; generation_id: string | null; baseline_state_sha256: string | null;
      fixture_evidence: unknown; baseline_evidence: unknown; registered_generation_id: string | null; registered_environment_id: string | null;
      binding_environment_id: string | null; binding_generation_id: string | null; binding_manifest_hash: string | null;
      binding_application_source_hash: string | null;
    }>;
  const prep = prepRows[0];
  const fence = object(prep?.fence_evidence);
  const fenceEvidence = fence ? parseEvidence(fence.evidence) : null;
  if (!prep || !fence || !fenceEvidence || prep.run_id !== run.id || prep.task_index !== predecessorIndex ||
      prep.preparation_id !== bundleRow!.preparation_id || prep.lease_id !== bundleRow!.lease_id || prep.environment_id !== bundleRow!.environment_id ||
      prep.release_identity !== run.release_identity || prep.manifest_hash !== run.manifest_hash || prep.task_id !== predecessor.task_id ||
      prep.case_id !== bundleRow!.case_id || prep.case_hash !== bundleRow!.case_hash || prep.initial_state_sha256 !== bundleRow!.initial_state_sha256 ||
      prep.execution_identity_hash !== bundleRow!.execution_identity_hash || prep.environment_manifest_sha256 !== bundleRow!.environment_manifest_hash ||
      prep.application_source_hash !== bundleRow!.application_source_hash || prep.lease_state !== 'fenced' || prep.preparation_status !== 'fenced' ||
      !prep.generation_id || prep.generation_id !== bundleRow!.generation_id || prep.registered_generation_id !== prep.generation_id ||
      prep.registered_environment_id !== prep.environment_id || prep.binding_environment_id !== prep.environment_id ||
      prep.binding_generation_id !== prep.generation_id || prep.binding_manifest_hash !== prep.environment_manifest_sha256 ||
      prep.binding_application_source_hash !== prep.application_source_hash || prep.baseline_state_sha256 !== prep.initial_state_sha256 ||
      !parseEvidence(asJson(prep.fixture_evidence)) || !parseEvidence(asJson(prep.baseline_evidence)) || fence.confirmed !== true ||
      fence.preparationId !== prep.preparation_id || fence.leaseId !== prep.lease_id || fence.environmentId !== prep.environment_id ||
      fence.generationId !== prep.generation_id) {
    fail(409, 'RUN_TASK_PREDECESSOR_NOT_FENCED', 'The predecessor generation is not exactly fenced and bound to its execution evidence');
  }

  const eventRows = await tx.execute(sql`SELECT source,payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${run.id} AND event_type='task.terminalized' ORDER BY sequence FOR KEY SHARE`) as unknown as Array<{
      source: string; payload_hash: string; payload_json: unknown;
    }>;
  const matchingEvents = eventRows.filter((event) => object(event.payload_json)?.taskIndex === predecessorIndex);
  const finishedAt = isoDate(predecessor.finished_at);
  if (!finishedAt) fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'The predecessor terminal timestamp is invalid');
  const expectedEvent = {
    runId: run.id, taskIndex: predecessorIndex, taskId: predecessor.task_id, closureId: predecessor.closure_id,
    releaseIdentity: run.release_identity, manifestHash: run.manifest_hash, inputHash: evaluation.input_hash,
    resultHash: evaluation.result_hash, outcome: result.outcome,
    status: result.outcome === 'failed' ? 'failed' : 'completed', finishedAt,
    preparationId: prep.preparation_id, leaseId: prep.lease_id, generationId: prep.generation_id,
    fenceEvidenceHash: fenceEvidence.sha256,
  };
  if (predecessor.status !== expectedEvent.status || matchingEvents.length !== 1 || matchingEvents[0]!.source !== 'coordinator' ||
      matchingEvents[0]!.payload_hash !== sha256CanonicalTaskJson(expectedEvent) || stableJson(object(matchingEvents[0]!.payload_json)) !== stableJson(expectedEvent)) {
    fail(409, 'RUN_TASK_TERMINALIZATION_EVENT_MISMATCH', 'The predecessor terminalization event is missing or inconsistent');
  }
  return validDate(predecessor.finished_at)!;
}

async function lockAndValidateCurrent(tx: Transaction, target: TaskPreparationTarget): Promise<RunRow> {
  const candidates = await tx.execute(sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`) as unknown as Array<{ owner_id: string; agent_id: string }>;
  if (!candidates[0]) fail(404, 'RUN_NOT_FOUND', 'The task preparation run does not exist');
  await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${candidates[0].owner_id} FOR NO KEY UPDATE`);
  await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${candidates[0].agent_id} AND owner_id=${candidates[0].owner_id} FOR NO KEY UPDATE`);
  const runs = await tx.execute(sql`SELECT r.id,r.owner_id,r.agent_id,r.mode,r.status,r.task_ids,r.release_identity,r.manifest_hash,
      r.access_generation,r.agent_policy_revision,(r.status<>'preparing' OR r.queue_deadline>clock_timestamp()) AS queue_live,
      COALESCE(r.overall_deadline>clock_timestamp(),r.status='preparing') AS overall_live,
      r.overall_deadline,r.successor_preparation_policy_version,r.successor_preparation_timeout_seconds,
      o.admission_status,a.access_generation AS current_access_generation,a.access_revoked_at,
      p.training,p.ranked,p.revision AS current_policy_revision
    FROM oid_benchmark_run r JOIN oid_owner o ON o.id=r.owner_id JOIN oid_agent a ON a.id=r.agent_id
    JOIN oid_agent_policy p ON p.agent_id=a.id
    WHERE r.id=${target.runId} AND r.owner_id=${candidates[0].owner_id} AND r.agent_id=${candidates[0].agent_id}
    FOR UPDATE OF r,a,p`) as unknown as Array<RunRow & {
      admission_status: string; current_access_generation: number; access_revoked_at: Date | string | null;
      training: boolean; ranked: boolean; current_policy_revision: number;
    }>;
  const run = runs[0];
  if (!run) fail(404, 'RUN_NOT_FOUND', 'The task preparation run does not exist');
  const claimRows = await tx.execute(sql`SELECT claim_id,status FROM oid_run_dispatch_claim WHERE run_id=${target.runId} FOR UPDATE`) as unknown as Array<{ claim_id: string; status: string }>;
  const slotRows = await tx.execute(sql`SELECT claim_id,state FROM oid_run_execution_slot
    WHERE run_id=${target.runId} AND released_at IS NULL FOR UPDATE`) as unknown as Array<{ claim_id: string; state: string }>;
  if (claimRows[0]?.claim_id !== target.claimId || claimRows[0]?.status !== 'claimed' || slotRows[0]?.claim_id !== target.claimId) {
    fail(409, 'STALE_RUN_CLAIM', 'The task preparation claim is no longer current');
  }
  const permission = run.mode === 'training' ? run.training : run.ranked;
  const historicalModeRemoval = await tx.execute(sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${run.owner_id} AND agent_id=${run.agent_id}
        AND mode=${run.mode} AND policy_revision>${run.agent_policy_revision}) AS exists`) as unknown as Array<{ exists: boolean }>;
  if (run.admission_status !== 'admitted' || !permission || run.access_revoked_at ||
      run.current_access_generation !== run.access_generation || historicalModeRemoval[0]?.exists) {
    fail(409, 'TASK_PREPARATION_ACCESS_REVOKED', 'Run access is no longer eligible for preparation');
  }
  if (target.taskIndex === 0) {
    const tasks = await tx.execute(sql`SELECT task_id,status,closure_status,deadline_at>clock_timestamp() AS task_live
      FROM oid_run_task WHERE run_id=${target.runId} AND task_index=0 FOR UPDATE`) as unknown as Array<{
        task_id: string; status: string; closure_status: string; task_live: boolean;
      }>;
    const task = tasks[0];
    const prestart = run.status === 'preparing' && slotRows[0]?.state === 'preparing' && task?.status === 'queued';
    if (!prestart || !run.queue_live || !run.overall_live || !task || task.task_id !== run.task_ids[0] || task.closure_status !== 'open') {
      fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'Only the queued first task of the current pre-start claim can be prepared');
    }
    return run;
  }

  if (run.status !== 'running' || slotRows[0]?.state !== 'running') {
    fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'A successor task requires the same running claim and execution slot');
  }
  const taskRows = await tx.execute(sql`SELECT task_index,task_id,status,closure_status,closure_id,closure_operation_id,
      closure_payload_hash,closure_reason,action_cutoff_sequence,reconciled_action_sequence,started_at,finished_at
    FROM oid_run_task WHERE run_id=${target.runId} ORDER BY task_index FOR UPDATE`) as unknown as LockedTaskRow[];
  const predecessorFinishedAt = await assertKnownPredecessorProof(tx, run, target.taskIndex, taskRows);
  assertSuccessorPreparationWindow(run, predecessorFinishedAt, await databaseNow(tx));
  const targetTask = taskRows[target.taskIndex];
  if (!targetTask || targetTask.task_id !== run.task_ids[target.taskIndex] || targetTask.status !== 'queued' || targetTask.closure_status !== 'open') {
    fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'Only the next exact queued task may be prepared');
  }

  const preparationRows = await tx.execute(sql`SELECT i.task_index,l.state AS lease_state
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l
      ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    WHERE i.run_id=${target.runId} ORDER BY i.task_index FOR UPDATE OF i,l`) as unknown as Array<{ task_index: number; lease_state: string }>;
  const priorPreparations = preparationRows.filter((row) => row.task_index < target.taskIndex);
  if (priorPreparations.length !== target.taskIndex || priorPreparations.some((row, index) => row.task_index !== index || row.lease_state !== 'fenced') ||
      preparationRows.some((row) => row.task_index > target.taskIndex || (row.task_index !== target.taskIndex && row.lease_state === 'leased'))) {
    fail(409, 'TASK_PREPARATION_PREDECESSOR_LEASE_ACTIVE', 'A predecessor or other task still holds an unfenced environment lease');
  }
  return run;
}

async function readIntent(tx: Transaction, preparationId: string, lock = false): Promise<{
  intent: IntentRow; observation: ObservationRow; lease: LeaseRow; dispatchStatus: 'dispatching' | 'completed' | 'unknown' | null;
} | null> {
  const suffix = lock ? sql`FOR UPDATE OF i,l` : sql``;
  const rows = await tx.execute(sql`SELECT i.preparation_id,i.run_id,i.task_index,i.claim_id,i.lease_id,i.environment_id,
      i.release_identity,i.manifest_hash,i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
      i.environment_manifest_sha256,i.application_source_hash,i.created_at,
      l.state AS lease_state,l.fence_evidence,d.state AS dispatch_state,
      o.revision,o.status,o.generation_id,o.participant_id,o.payer_address,o.baseline_state_sha256,
      o.fixture_evidence,o.baseline_evidence,o.reason_code,o.created_at AS observation_created_at
    FROM oid_task_preparation_intent i
    JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id
    LEFT JOIN oid_task_preparation_dispatch d ON d.preparation_id=i.preparation_id
    JOIN LATERAL (SELECT * FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    WHERE i.preparation_id=${preparationId} ${suffix}`) as unknown as Array<IntentRow & {
      lease_state: 'leased' | 'fenced'; fence_evidence: unknown; dispatch_state: 'dispatching' | 'completed' | 'unknown' | null;
      revision: number; status: PreparationStatus;
      generation_id: string | null; participant_id: string | null; payer_address: string | null; baseline_state_sha256: string | null;
      fixture_evidence: unknown; baseline_evidence: unknown; reason_code: PreparationUnknownReason | null; observation_created_at: Date | string;
    }>;
  const row = rows[0];
  if (!row) return null;
  return {
    intent: row,
    observation: {
      revision: row.revision, status: row.status, generation_id: row.generation_id, participant_id: row.participant_id,
      payer_address: row.payer_address, baseline_state_sha256: row.baseline_state_sha256, fixture_evidence: row.fixture_evidence,
      baseline_evidence: row.baseline_evidence, reason_code: row.reason_code, created_at: row.observation_created_at,
    },
    lease: { state: row.lease_state, fence_evidence: row.fence_evidence }, dispatchStatus: row.dispatch_state,
  };
}

function view(row: NonNullable<Awaited<ReturnType<typeof readIntent>>>): TaskPreparationRecord {
  return { intent: rowToIntent(row.intent), observation: rowToObservation(row.observation), leaseStatus: row.lease.state,
    dispatchStatus: row.dispatchStatus };
}

async function latestObservation(tx: Transaction, preparationId: string, lock = false): Promise<ObservationRow | null> {
  const rows = await tx.execute(sql`SELECT revision,status,generation_id,participant_id,payer_address,baseline_state_sha256,
      fixture_evidence,baseline_evidence,reason_code,created_at FROM oid_task_preparation_observation
    WHERE preparation_id=${preparationId} ORDER BY revision DESC LIMIT 1 ${lock ? sql`FOR UPDATE` : sql``}`) as unknown as ObservationRow[];
  return rows[0] ?? null;
}

async function appendObservation(tx: Transaction, input: {
  preparationId: string; status: PreparationStatus; generationId?: string | null; participantId?: string | null;
  payerAddress?: string | null; baselineStateSha256?: string | null; fixtureEvidence?: EvidenceReference | null;
  baselineEvidence?: EvidenceReference | null; reasonCode?: PreparationUnknownReason | null;
}): Promise<void> {
  const latest = await latestObservation(tx, input.preparationId, true);
  const revision = (latest?.revision ?? 0) + 1;
  await tx.execute(sql`INSERT INTO oid_task_preparation_observation(
      preparation_id,revision,status,generation_id,participant_id,payer_address,baseline_state_sha256,
      fixture_evidence,baseline_evidence,reason_code)
    VALUES (${input.preparationId},${revision},${input.status},${input.generationId ?? latest?.generation_id ?? null},
      ${input.participantId ?? null},${input.payerAddress ?? null},${input.baselineStateSha256 ?? null},
      ${input.fixtureEvidence ? JSON.stringify(input.fixtureEvidence) : null}::jsonb,
      ${input.baselineEvidence ? JSON.stringify(input.baselineEvidence) : null}::jsonb,${input.reasonCode ?? null})`);
}

async function claimInitialDispatch(db: OwnerDatabase, preparationId: string): Promise<{
  claimed: boolean; dispatchId: string | null; preparation: TaskPreparationRecord;
}> {
  return db.transaction(async (tx) => {
    const targets = await tx.execute(sql`SELECT run_id,task_index,claim_id FROM oid_task_preparation_intent
      WHERE preparation_id=${preparationId}`) as unknown as Array<{ run_id: string; task_index: number; claim_id: string }>;
    if (!targets[0]) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
    await lockAndValidateCurrent(tx, { runId: targets[0].run_id, taskIndex: targets[0].task_index, claimId: targets[0].claim_id });
    const intents = await tx.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent
      WHERE preparation_id=${preparationId} FOR UPDATE`) as unknown as Array<{ preparation_id: string }>;
    if (!intents[0]) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
    const existing = await tx.execute(sql`SELECT dispatch_id,state FROM oid_task_preparation_dispatch
      WHERE preparation_id=${preparationId}`) as unknown as Array<{ dispatch_id: string; state: 'dispatching' | 'completed' | 'unknown' }>;
    if (existing[0]) {
      const record = await readIntent(tx, preparationId);
      if (!record) throw new Error('Task preparation dispatch has no immutable intent');
      return { claimed: false, dispatchId: existing[0].dispatch_id, preparation: view(record) };
    }
    const dispatchId = randomUUID();
    await tx.execute(sql`INSERT INTO oid_task_preparation_dispatch(preparation_id,dispatch_id)
      VALUES (${preparationId},${dispatchId})`);
    const record = await readIntent(tx, preparationId);
    if (!record) throw new Error('New task preparation dispatch could not be read back');
    return { claimed: true, dispatchId, preparation: view(record) };
  });
}

async function settleInitialDispatch(db: OwnerDatabase, input: {
  preparationId: string; dispatchId: string; state: 'completed' | 'unknown';
}): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent WHERE preparation_id=${input.preparationId} FOR UPDATE`);
    const rows = await tx.execute(sql`SELECT dispatch_id,state FROM oid_task_preparation_dispatch
      WHERE preparation_id=${input.preparationId} FOR UPDATE`) as unknown as Array<{ dispatch_id: string; state: 'dispatching' | 'completed' | 'unknown' }>;
    const dispatch = rows[0];
    if (!dispatch || dispatch.dispatch_id !== input.dispatchId) fail(409, 'TASK_PREPARATION_DISPATCH_MISMATCH', 'The dispatch callback is not the original preparation attempt');
    if (dispatch.state === input.state) return;
    if (dispatch.state !== 'dispatching') fail(409, 'TASK_PREPARATION_DISPATCH_SETTLED', 'The original preparation dispatch is already settled');
    await tx.execute(sql`UPDATE oid_task_preparation_dispatch SET state=${input.state},settled_at=clock_timestamp()
      WHERE preparation_id=${input.preparationId} AND dispatch_id=${input.dispatchId} AND state='dispatching'`);
  });
}

function validateReadyResult(result: TrustedTaskPreparationResult, intent: TaskPreparationIntentPins): { fixture: EvidenceReference; baseline: EvidenceReference } {
  const fixture = parseEvidence(result.fixtureEvidence), baseline = parseEvidence(result.baselineEvidence);
  if (!UUID.test(result.generationId) || result.environmentId !== intent.environmentId ||
      result.manifestHash.toLowerCase() !== intent.manifestHash || result.applicationSourceHash.toLowerCase() !== intent.applicationSourceHash ||
      result.environmentManifestSha256.toLowerCase() !== intent.environmentManifestSha256 ||
      result.initialStateSha256.toLowerCase() !== intent.initialStateSha256 || !fixture || !baseline ||
      (result.participantId !== undefined && (!result.participantId.length || result.participantId.length > 160 || /[\u0000-\u001f]/.test(result.participantId))) ||
      (result.payerAddress !== undefined && !/^0x[0-9a-f]{40}$/i.test(result.payerAddress))) {
    fail(409, 'TASK_PREPARATION_RESULT_MISMATCH', 'Trusted preparation output does not match the sealed case and environment pins');
  }
  return { fixture, baseline };
}

async function loadPreparationForCallback(tx: Transaction, input: { preparationId: string; leaseId: string; claimId: string }) {
  if (!UUID.test(input.preparationId) || !UUID.test(input.leaseId) || !UUID.test(input.claimId)) {
    fail(400, 'INVALID_TASK_PREPARATION_CALLBACK', 'A preparation, lease, and claim identity are required');
  }
  const row = await readIntent(tx, input.preparationId, true);
  if (!row) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
  const intent = rowToIntent(row.intent);
  if (intent.leaseId !== input.leaseId.toLowerCase() || intent.claimId !== input.claimId.toLowerCase()) {
    fail(409, 'TASK_PREPARATION_CALLBACK_MISMATCH', 'Callback identities do not match the immutable preparation intent');
  }
  return { row, intent, observation: rowToObservation(row.observation) };
}

type SuccessorPredecessorReplayDependencies = Pick<TaskPreparationDependencies, 'db' | 'releaseSource'> &
  Pick<SuccessorTaskPreparationDependencies, 'predecessorEvidenceSource'>;

// AICODE-NOTE: Successors are explicit training-only entries. Replay the already terminal predecessor outside this transaction, then recheck its immutable evidence, evaluation, terminal event, execution binding, and fence under the run locks before any successor preparation work.
async function assertSuccessorPredecessorReplay(deps: SuccessorPredecessorReplayDependencies, target: TaskPreparationTarget): Promise<void> {
  if (target.taskIndex < 1) fail(400, 'INVALID_SUCCESSOR_TASK_INDEX', 'A successor task index must be at least one');
  const rows = await deps.db.execute(sql`SELECT r.id,r.status,r.mode,r.task_ids,t.task_id,t.status AS task_status,t.finished_at,
      e.task_id AS evaluation_task_id,e.input_hash,e.result_hash,e.input_json,e.result_json
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=${target.taskIndex - 1}
    LEFT JOIN oid_run_task_evaluation e ON e.run_id=r.id AND e.task_index=${target.taskIndex - 1}
    WHERE r.id=${target.runId}`) as unknown as Array<{
      id: string; status: string; mode: TaskMode; task_ids: string[]; task_id: string; task_status: string; finished_at: Date | string | null;
      evaluation_task_id: string | null; input_hash: string | null; result_hash: string | null; input_json: unknown; result_json: unknown;
    }>;
  const predecessor = rows[0];
  if (!predecessor || predecessor.status !== 'running' || !['training', 'ranked'].includes(predecessor.mode) ||
      target.taskIndex >= predecessor.task_ids.length || predecessor.task_ids[target.taskIndex - 1] !== predecessor.task_id ||
      (predecessor.task_status !== 'completed' && predecessor.task_status !== 'failed') || !validDate(predecessor.finished_at)) {
    fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'Successor preparation requires an already terminal predecessor');
  }
  const result = predecessor.evaluation_task_id === predecessor.task_id && hash(predecessor.input_hash) && hash(predecessor.result_hash) &&
      sha256CanonicalTaskJson(asJson(predecessor.input_json)) === predecessor.input_hash &&
      sha256CanonicalTaskJson(asJson(predecessor.result_json)) === predecessor.result_hash
    ? readKnownCanonicalEvaluationForMode(predecessor.result_json, predecessor.input_json, predecessor.task_id, predecessor.id, predecessor.mode)
    : null;
  if (!result || (result.outcome === 'failed') !== (predecessor.task_status === 'failed')) {
    fail(409, 'RUN_TASK_PREDECESSOR_NOT_KNOWN', 'Successor preparation requires the exact canonical known predecessor evaluation');
  }
  const finalize = predecessor.mode === 'ranked' ? finalizeKnownRankedTask : finalizeKnownTrainingTask;
  const proof = await finalize({
    db: deps.db, taskReleaseSource: deps.releaseSource, evidenceSource: deps.predecessorEvidenceSource,
  }, { runId: target.runId, taskIndex: target.taskIndex - 1 });
  if (!proof.replayed || proof.runId !== target.runId || proof.taskIndex !== target.taskIndex - 1 ||
      proof.taskId !== predecessor.task_id || proof.status !== predecessor.task_status ||
      new Date(proof.finishedAt).getTime() !== validDate(predecessor.finished_at)!.getTime()) {
    fail(409, 'RUN_TASK_PREDECESSOR_REPLAY_MISMATCH', 'The predecessor did not pass exact immutable evidence replay');
  }
}

async function beginTaskPreparationInternal(deps: TaskPreparationDependencies, target: TaskPreparationTarget): Promise<{ preparation: TaskPreparationRecord; replayed: boolean }> {
  const initialRows = await deps.db.execute(sql`SELECT release_identity,manifest_hash FROM oid_benchmark_run WHERE id=${target.runId}`) as unknown as Array<{ release_identity: string; manifest_hash: string }>;
  if (!initialRows[0]) fail(404, 'RUN_NOT_FOUND', 'The task preparation run does not exist');
  const preflightRelease = await deps.releaseSource.getValidatedReleaseRecord(initialRows[0].release_identity, initialRows[0].manifest_hash);
  if (!preflightRelease) fail(409, 'TASK_PREPARATION_RELEASE_UNAVAILABLE', 'The run has no validated sealed release');
  const prepId = randomUUID(), leaseId = randomUUID();
  let selectedEnvironment: string | null = null;
  const existingRows = await deps.db.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent
    WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{ preparation_id: string }>;
  if (!existingRows[0]) {
    const runMeta = await deps.db.execute(sql`SELECT id,owner_id,agent_id,mode,status,task_ids,release_identity,manifest_hash,
        access_generation,agent_policy_revision,queue_deadline>clock_timestamp() AS queue_live,
        COALESCE(overall_deadline>clock_timestamp(),status='preparing') AS overall_live
      FROM oid_benchmark_run WHERE id=${target.runId}`) as unknown as RunRow[];
    if (!runMeta[0]) fail(404, 'RUN_NOT_FOUND', 'The task preparation run does not exist');
    const pins = derivePins(preflightRelease, runMeta[0], target);
    const taskCase = preflightRelease.manifest.cases[runMeta[0].mode].find((entry) => entry.taskId === pins.taskId);
    if (!taskCase) fail(409, 'TASK_PREPARATION_CASE_UNAVAILABLE', 'The exact task case is not present in the validated sealed release');
    selectedEnvironment = await deps.environmentSelector.selectEnvironment({
      runId: target.runId, taskIndex: target.taskIndex, manifestHash: pins.manifestHash,
      environmentManifestSha256: pins.environmentManifestSha256, taskCase,
    });
    if (!validEnvironmentId(selectedEnvironment)) fail(503, 'TASK_ENVIRONMENT_UNAVAILABLE', 'No allowlisted environment was selected');
  }

  return deps.db.transaction(async (tx) => {
    const run = await lockAndValidateCurrent(tx, target);
    const release = await deps.releaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
    if (!release) fail(409, 'TASK_PREPARATION_RELEASE_UNAVAILABLE', 'The run has no validated sealed release');
    const pins = derivePins(release, run, target);
    const priorRows = await tx.execute(sql`SELECT * FROM oid_task_preparation_intent WHERE run_id=${target.runId}
      AND task_index=${target.taskIndex} FOR UPDATE`) as unknown as IntentRow[];
    if (priorRows[0]) {
      const prior = rowToIntent(priorRows[0]);
      if (!samePins(prior, pins)) fail(409, 'TASK_PREPARATION_INTENT_MISMATCH', 'An existing preparation has different sealed pins or claim');
      const record = await readIntent(tx, prior.preparationId);
      if (!record) throw new Error('Persisted task preparation has no observation or lease');
      return { preparation: view(record), replayed: true };
    }
    if (!selectedEnvironment) fail(503, 'TASK_ENVIRONMENT_UNAVAILABLE', 'No allowlisted environment was selected');
    const intent = {
      preparationId: prepId, leaseId, environmentId: selectedEnvironment,
      ...pins,
    };
    await tx.execute(sql`INSERT INTO oid_task_preparation_intent(
        preparation_id,run_id,task_index,claim_id,lease_id,environment_id,release_identity,manifest_hash,task_id,case_id,
        case_hash,initial_state_sha256,execution_identity_hash,environment_manifest_sha256,application_source_hash)
      VALUES (${intent.preparationId},${intent.runId},${intent.taskIndex},${intent.claimId},${intent.leaseId},${intent.environmentId},
        ${intent.releaseIdentity},${intent.manifestHash},${intent.taskId},${intent.caseId},${intent.caseHash},${intent.initialStateSha256},
        ${intent.executionIdentityHash},${intent.environmentManifestSha256},${intent.applicationSourceHash})`);
    const leaseInsert = await tx.execute(sql`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id)
      VALUES (${leaseId},${prepId},${selectedEnvironment}) ON CONFLICT DO NOTHING RETURNING lease_id`) as unknown as Array<{ lease_id: string }>;
    if (!leaseInsert[0]) fail(409, 'TASK_ENVIRONMENT_BUSY', 'The selected environment already has an unfenced preparation lease');
    await appendObservation(tx, { preparationId: prepId, status: 'preparing' });
    const record = await readIntent(tx, prepId);
    if (!record) throw new Error('New task preparation could not be read back');
    return { preparation: view(record), replayed: false };
  });
}

/** The original API remains first-task-only. */
export async function beginTaskPreparation(deps: TaskPreparationDependencies, target: TaskPreparationTarget): Promise<{ preparation: TaskPreparationRecord; replayed: boolean }> {
  target = normalizeTarget(target);
  if (target.taskIndex !== 0) fail(409, 'FIRST_TASK_PREPARATION_REQUIRED', 'Use the explicit successor preparation API for later tasks');
  return beginTaskPreparationInternal(deps, target);
}

/** Creates a later task preparation only after the exact terminal predecessor replays as known. */
export async function beginSuccessorTaskPreparation(
  deps: SuccessorTaskPreparationDependencies,
  target: TaskPreparationTarget,
): Promise<{ preparation: TaskPreparationRecord; replayed: boolean }> {
  target = normalizeTarget(target);
  if (target.taskIndex < 1) fail(400, 'INVALID_SUCCESSOR_TASK_INDEX', 'A successor task index must be at least one');
  await assertSuccessorPredecessorReplay(deps, target);
  return beginTaskPreparationInternal(deps, target);
}

export async function getTaskPreparation(db: OwnerDatabase, preparationId: string): Promise<TaskPreparationRecord | null> {
  if (!UUID.test(preparationId)) fail(400, 'INVALID_TASK_PREPARATION_ID', 'A preparation UUID is required');
  return db.transaction(async (tx) => {
    const row = await readIntent(tx, preparationId);
    return row ? view(row) : null;
  });
}

async function recordTaskPreparationUnknown(db: OwnerDatabase, input: {
  preparationId: string; leaseId: string; claimId: string; generationId?: string | null; reasonCode: PreparationUnknownReason;
}): Promise<{ preparation: TaskPreparationRecord; replayed: boolean }> {
  if (input.generationId !== undefined && input.generationId !== null && !UUID.test(input.generationId)) {
    fail(400, 'INVALID_TASK_PREPARATION_GENERATION', 'Generation identity must be a UUID');
  }
  return db.transaction(async (tx) => {
    const targetRows = await tx.execute(sql`SELECT run_id,task_index,claim_id FROM oid_task_preparation_intent
      WHERE preparation_id=${input.preparationId}`) as unknown as Array<{ run_id: string; task_index: number; claim_id: string }>;
    if (!targetRows[0]) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
    if (targetRows[0].task_index > 0) {
      if (targetRows[0].claim_id !== input.claimId.toLowerCase()) {
        fail(409, 'TASK_PREPARATION_CALLBACK_MISMATCH', 'Callback claim does not match the immutable preparation intent');
      }
      await lockAndValidateCurrent(tx, { runId: targetRows[0].run_id, taskIndex: targetRows[0].task_index,
        claimId: input.claimId.toLowerCase() });
    }
    const { row, intent, observation } = await loadPreparationForCallback(tx, input);
    if (row.lease.state !== 'leased') fail(409, 'TASK_PREPARATION_LEASE_FENCED', 'A fenced lease cannot receive preparation callbacks');
    const generationId = input.generationId?.toLowerCase() ?? observation.generationId;
    if (observation.generationId && generationId !== observation.generationId) {
      fail(409, 'TASK_PREPARATION_GENERATION_MISMATCH', 'The callback cannot replace the original generation identity');
    }
    if (observation.status === 'unknown' && !observation.generationId && generationId) {
      fail(409, 'TASK_PREPARATION_ORIGINAL_GENERATION_UNKNOWN', 'An unknown preparation cannot infer its original generation later');
    }
    if (observation.status === 'ready' || observation.status === 'fenced') {
      fail(409, 'TASK_PREPARATION_TERMINAL', 'A ready or fenced preparation cannot become unknown');
    }
    if (observation.status === 'unknown' && observation.generationId === generationId && observation.reasonCode === input.reasonCode) {
      return { preparation: view(row), replayed: true };
    }
    await appendObservation(tx, { preparationId: intent.preparationId, status: 'unknown', generationId, reasonCode: input.reasonCode });
    const updated = await readIntent(tx, intent.preparationId);
    if (!updated) throw new Error('Unknown preparation could not be read back');
    return { preparation: view(updated), replayed: false };
  });
}

async function recordTaskPreparationReady(db: OwnerDatabase, input: {
  preparationId: string; leaseId: string; claimId: string; result: TrustedTaskPreparationResult;
}): Promise<{ preparation: TaskPreparationRecord; replayed: boolean }> {
  return db.transaction(async (tx) => {
    if (!UUID.test(input.preparationId) || !UUID.test(input.leaseId) || !UUID.test(input.claimId)) {
      fail(400, 'INVALID_TASK_PREPARATION_CALLBACK', 'A preparation, lease, and claim identity are required');
    }
    const targetRows = await tx.execute(sql`SELECT run_id,task_index,claim_id FROM oid_task_preparation_intent
      WHERE preparation_id=${input.preparationId}`) as unknown as Array<{ run_id: string; task_index: number; claim_id: string }>;
    if (!targetRows[0]) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
    if (targetRows[0].claim_id !== input.claimId.toLowerCase()) {
      fail(409, 'TASK_PREPARATION_CALLBACK_MISMATCH', 'Callback claim does not match the immutable preparation intent');
    }
    const current = await lockAndValidateCurrent(tx, {
      runId: targetRows[0].run_id, taskIndex: targetRows[0].task_index, claimId: input.claimId.toLowerCase(),
    });
    const { row, intent, observation } = await loadPreparationForCallback(tx, input);
    if (row.lease.state !== 'leased') fail(409, 'TASK_PREPARATION_LEASE_FENCED', 'A fenced lease cannot become ready');
    const result = validateReadyResult(input.result, intent);
    if (observation.status === 'fenced') fail(409, 'TASK_PREPARATION_TERMINAL', 'A fenced preparation cannot become ready');
    if (observation.generationId && observation.generationId !== input.result.generationId.toLowerCase()) {
      fail(409, 'TASK_PREPARATION_GENERATION_MISMATCH', 'Readiness must reconcile the original generation');
    }
    if (observation.status === 'unknown' && !observation.generationId) {
      fail(409, 'TASK_PREPARATION_ORIGINAL_GENERATION_UNKNOWN', 'Unknown preparation without an original generation cannot become ready');
    }
    const release = await (async () => {
      // Rechecking the run pin under its lock prevents a callback from becoming ready for a stale/cancelled claim.
      const source = await tx.execute(sql`SELECT release_identity,manifest_hash FROM oid_benchmark_run WHERE id=${intent.runId}`) as unknown as Array<{ release_identity: string; manifest_hash: string }>;
      if (!source[0] || source[0].release_identity !== intent.releaseIdentity || source[0].manifest_hash !== intent.manifestHash) return null;
      return source[0];
    })();
    if (!current || !release) fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'The claimed run is no longer eligible for ready preparation');
    if (observation.status === 'ready') {
      const same = observation.generationId === input.result.generationId.toLowerCase() &&
        observation.baselineStateSha256 === intent.initialStateSha256 && observation.participantId === (input.result.participantId ?? null) &&
        observation.payerAddress === (input.result.payerAddress?.toLowerCase() ?? null) &&
        stableJson(observation.fixtureEvidence) === stableJson(result.fixture) &&
        stableJson(observation.baselineEvidence) === stableJson(result.baseline);
      if (!same) fail(409, 'TASK_PREPARATION_READY_IMMUTABLE', 'A ready preparation identity and evidence cannot be replaced');
      return { preparation: view(row), replayed: true };
    }
    await appendObservation(tx, {
      preparationId: intent.preparationId, status: 'ready', generationId: input.result.generationId.toLowerCase(),
      participantId: input.result.participantId ?? null, payerAddress: input.result.payerAddress?.toLowerCase() ?? null,
      baselineStateSha256: input.result.initialStateSha256.toLowerCase(), fixtureEvidence: result.fixture,
      baselineEvidence: result.baseline,
    });
    const updated = await readIntent(tx, intent.preparationId);
    if (!updated) throw new Error('Ready preparation could not be read back');
    return { preparation: view(updated), replayed: false };
  });
}

async function assertTaskPreparationReadyInternal(db: OwnerDatabase, target: TaskPreparationTarget): Promise<TaskPreparationRecord> {
  return db.transaction(async (tx) => {
    await lockAndValidateCurrent(tx, target);
    const rows = await tx.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex} AND claim_id=${target.claimId}`) as unknown as Array<{ preparation_id: string }>;
    if (!rows[0]) fail(409, 'TASK_PREPARATION_NOT_READY', 'No preparation matches this exact run/task/claim');
    const record = await readIntent(tx, rows[0].preparation_id, true);
    if (!record || record.observation.status !== 'ready' || record.lease.state !== 'leased' || !record.observation.generation_id ||
        record.observation.baseline_state_sha256 !== record.intent.initial_state_sha256 ||
        !parseEvidence(record.observation.fixture_evidence) || !parseEvidence(record.observation.baseline_evidence)) {
      fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact claimed task has no verified, unfenced baseline preparation');
    }
    return view(record);
  });
}

export async function assertTaskPreparationReady(db: OwnerDatabase, target: TaskPreparationTarget): Promise<TaskPreparationRecord> {
  target = normalizeTarget(target);
  if (target.taskIndex !== 0) fail(409, 'FIRST_TASK_PREPARATION_REQUIRED', 'Use the explicit successor readiness API for later tasks');
  return assertTaskPreparationReadyInternal(db, target);
}

export async function assertSuccessorTaskPreparationReady(
  deps: SuccessorTaskPreparationDependencies,
  target: TaskPreparationTarget,
): Promise<TaskPreparationRecord> {
  target = normalizeTarget(target);
  if (target.taskIndex < 1) fail(400, 'INVALID_SUCCESSOR_TASK_INDEX', 'A successor task index must be at least one');
  await assertSuccessorPredecessorReplay(deps, target);
  return assertTaskPreparationReadyInternal(deps.db, target);
}

/**
 * Builds the strict run-start boundary over the exact durable preparation. The
 * transaction validator assumes the caller already holds the owner, agent,
 * run, claim, and slot locks; it never opens or commits a transaction itself.
 */
function createPreparedTaskStartPortInternal(
  deps: Pick<TaskPreparationDependencies, 'db' | 'releaseSource' | 'preparationAdapter'> &
    Partial<Pick<SuccessorTaskPreparationDependencies, 'predecessorEvidenceSource'>>,
  attachStartedSession: (preparation: TaskPreparationRecord, minimumValidUntil: string) => Promise<void>,
  successor: boolean,
): PreparedTaskStartPort {
  const predecessorReplayCandidates = new Set<string>();
  return {
    async readCandidatePreparationId(target) {
      const normalized = normalizeTarget(target);
      if (successor) {
        if (normalized.taskIndex < 1 || !deps.predecessorEvidenceSource) {
          fail(409, 'TASK_PREPARATION_NOT_READY', 'A successor start requires a verified predecessor evidence source');
        }
        await assertSuccessorPredecessorReplay({ db: deps.db, releaseSource: deps.releaseSource,
          predecessorEvidenceSource: deps.predecessorEvidenceSource }, normalized);
      } else if (normalized.taskIndex !== 0) {
        fail(409, 'FIRST_TASK_PREPARATION_REQUIRED', 'The original run-start port accepts only task zero');
      }
      const rows = await deps.db.execute(sql`SELECT preparation_id FROM oid_task_preparation_intent
        WHERE run_id=${normalized.runId} AND task_index=${normalized.taskIndex}`) as unknown as Array<{ preparation_id: string }>;
      if (successor && rows[0]) predecessorReplayCandidates.add(`${normalized.runId}:${normalized.taskIndex}:${rows[0].preparation_id}`);
      return rows[0]?.preparation_id ?? null;
    },
    async assertReadyInTransaction(tx, target, preparationId, minimumValidUntil) {
      const normalized = normalizeTarget(target);
      const minimumTime = Date.parse(minimumValidUntil);
      if ((!successor && normalized.taskIndex !== 0) || (successor && normalized.taskIndex < 1) ||
          !UUID.test(preparationId) || !Number.isFinite(minimumTime)) {
        fail(409, 'TASK_PREPARATION_NOT_READY', 'The preparation identity does not match this run-start port');
      }
      if (successor && !predecessorReplayCandidates.delete(`${normalized.runId}:${normalized.taskIndex}:${preparationId}`)) {
        fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact predecessor must be replayed before a successor start');
      }
      let run: RunRow | null = null;
      if (successor) run = await lockAndValidateCurrent(tx, normalized);
      if (!run) {
        const runRows = await tx.execute(sql`SELECT r.id,r.owner_id,r.agent_id,r.mode,r.status,r.task_ids,r.release_identity,r.manifest_hash,
          r.access_generation,r.agent_policy_revision,r.queue_deadline>clock_timestamp() AS queue_live,
          COALESCE(r.overall_deadline>clock_timestamp(),r.status='preparing') AS overall_live,
          r.overall_deadline,r.successor_preparation_policy_version,r.successor_preparation_timeout_seconds
          FROM oid_benchmark_run r WHERE r.id=${normalized.runId}`) as unknown as RunRow[];
        run = runRows[0] ?? null;
      }
      const eligibleRun = run && (successor
        ? run.status === 'running'
        : run.status === 'preparing' && run.queue_live && run.overall_live);
      if (!run || !eligibleRun) {
        fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'The exact run is no longer eligible to start this task');
      }
      const claimRows = await tx.execute(sql`SELECT claim_id,status FROM oid_run_dispatch_claim
        WHERE run_id=${normalized.runId}`) as unknown as Array<{ claim_id: string; status: string }>;
      const slotRows = await tx.execute(sql`SELECT claim_id,state FROM oid_run_execution_slot
        WHERE run_id=${normalized.runId} AND released_at IS NULL`) as unknown as Array<{ claim_id: string; state: string }>;
      if (claimRows[0]?.claim_id !== normalized.claimId || claimRows[0]?.status !== 'claimed' ||
          slotRows[0]?.claim_id !== normalized.claimId || slotRows[0]?.state !== (successor ? 'running' : 'preparing')) {
        fail(409, 'STALE_RUN_CLAIM', 'The preparation claim or execution slot is no longer current');
      }
      const taskRows = await tx.execute(sql`SELECT task_id,status,closure_status FROM oid_run_task
        WHERE run_id=${normalized.runId} AND task_index=${normalized.taskIndex}`) as unknown as Array<{ task_id: string; status: string; closure_status: string }>;
      if (!taskRows[0] || taskRows[0].task_id !== run.task_ids[normalized.taskIndex] || taskRows[0].status !== 'queued' ||
          taskRows[0].closure_status !== 'open') {
        fail(409, 'TASK_PREPARATION_RUN_NOT_CURRENT', 'Only the exact queued task may be activated');
      }
      const release = await deps.releaseSource.getValidatedReleaseRecord(
        run.release_identity, run.manifest_hash, tx as TaskReleaseTransaction,
      );
      if (!release) fail(409, 'TASK_PREPARATION_RELEASE_UNAVAILABLE', 'The exact sealed release is no longer validated');
      const expectedPins = derivePins(release, run, normalized);
      const row = await readIntent(tx, preparationId, true);
      if (!row) fail(409, 'TASK_PREPARATION_NOT_READY', 'The candidate preparation no longer exists');
      const intent = rowToIntent(row.intent);
      if (intent.runId !== normalized.runId || intent.taskIndex !== normalized.taskIndex || intent.claimId !== normalized.claimId ||
          !samePins(intent, expectedPins) || !validEnvironmentId(intent.environmentId)) {
        fail(409, 'TASK_PREPARATION_PIN_MISMATCH', 'The prepared identity does not match the current run, claim, and sealed case');
      }
      const observation = rowToObservation(row.observation);
      if (row.lease.state === 'fenced' || observation.status === 'fenced') {
        fail(409, 'TASK_PREPARATION_FENCED', 'The original preparation lease is already fenced and cannot start');
      }
      const generationRows = observation.generationId
        ? await tx.execute(sql`SELECT generation_id,preparation_id,environment_id FROM oid_task_preparation_generation
            WHERE preparation_id=${preparationId} AND generation_id=${observation.generationId}`) as unknown as Array<{
              generation_id: string; preparation_id: string; environment_id: string;
            }>
        : [];
      if (observation.status !== 'ready' || row.lease.state !== 'leased' || row.dispatchStatus !== 'completed' ||
          !observation.generationId || !UUID.test(observation.generationId) ||
          generationRows[0]?.preparation_id !== preparationId || generationRows[0]?.environment_id !== intent.environmentId ||
          observation.baselineStateSha256 !== intent.initialStateSha256 ||
          !parseEvidence(observation.fixtureEvidence) || !parseEvidence(observation.baselineEvidence)) {
        fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact preparation must be ready, leased, dispatched once, and baseline-verified');
      }
      if (!deps.preparationAdapter.hasUsableStartSession?.(intent, new Date(minimumTime).toISOString())) {
        fail(409, 'TASK_PREPARATION_SESSION_UNAVAILABLE', 'The original RAM session does not cover this task deadline');
      }
      return view(row);
    },
    hasUsableStartSession(preparation, minimumValidUntil) {
      return Boolean(deps.preparationAdapter.hasUsableStartSession?.(preparation.intent, minimumValidUntil));
    },
    async attachStartedSession(preparation, minimumValidUntil) {
      await attachStartedSession(preparation, minimumValidUntil);
    },
  };
}

export function createPreparedTaskStartPort(
  deps: Pick<TaskPreparationDependencies, 'db' | 'releaseSource' | 'preparationAdapter'>,
  attachStartedSession: (preparation: TaskPreparationRecord, minimumValidUntil: string) => Promise<void>,
): PreparedTaskStartPort {
  return createPreparedTaskStartPortInternal(deps, attachStartedSession, false);
}

export function createPreparedSuccessorTaskStartPort(
  deps: Pick<SuccessorTaskPreparationDependencies, 'db' | 'releaseSource' | 'preparationAdapter' | 'predecessorEvidenceSource'>,
  attachStartedSession: (preparation: TaskPreparationRecord, minimumValidUntil: string) => Promise<void>,
): PreparedTaskStartPort {
  return createPreparedTaskStartPortInternal(deps, attachStartedSession, true);
}

async function fenceAndReleaseTaskEnvironmentLease(db: OwnerDatabase, input: ConfirmedTaskEnvironmentFence): Promise<{ released: boolean; replayed: boolean }> {
  if (input.confirmed !== true || !UUID.test(input.preparationId) || !UUID.test(input.leaseId) ||
      (input.generationId !== null && !UUID.test(input.generationId)) || !validEnvironmentId(input.environmentId)) {
    fail(400, 'INVALID_TASK_ENVIRONMENT_FENCE', 'A confirmed fence must name its exact preparation, lease, environment, and generation');
  }
  const evidence = parseEvidence(input.evidence);
  if (!evidence) fail(400, 'INVALID_TASK_ENVIRONMENT_FENCE', 'Fence evidence must be a hash-backed raw evidence reference');
  return db.transaction(async (tx) => {
    const row = await readIntent(tx, input.preparationId, true);
    if (!row) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
    const intent = rowToIntent(row.intent), observation = rowToObservation(row.observation);
    if (intent.leaseId !== input.leaseId.toLowerCase() || intent.environmentId !== input.environmentId ||
        observation.generationId !== input.generationId?.toLowerCase() && !(observation.generationId === null && input.generationId === null)) {
      fail(409, 'TASK_ENVIRONMENT_FENCE_MISMATCH', 'Fence evidence does not match the immutable lease identity');
    }
    const canonicalFence = {
      confirmed: true, preparationId: input.preparationId.toLowerCase(), leaseId: input.leaseId.toLowerCase(),
      environmentId: input.environmentId, generationId: input.generationId?.toLowerCase() ?? null, evidence,
    };
    if (row.lease.state === 'fenced') {
      if (stableJson(asJson(row.lease.fence_evidence)) !== stableJson(canonicalFence)) {
        fail(409, 'TASK_ENVIRONMENT_FENCE_IMMUTABLE', 'A prior lease release receipt cannot be replaced');
      }
      await tx.execute(sql`UPDATE oid_task_preparation_dispatch SET state='unknown',settled_at=clock_timestamp()
        WHERE preparation_id=${intent.preparationId} AND state='dispatching'`);
      return { released: true, replayed: true };
    }
    await tx.execute(sql`UPDATE oid_task_environment_lease SET state='fenced',fence_evidence=${JSON.stringify(canonicalFence)}::jsonb,
      fenced_at=clock_timestamp() WHERE lease_id=${intent.leaseId} AND preparation_id=${intent.preparationId} AND state='leased'`);
    // A cancellation fence settles any original PUT dispatch whose response
    // never reached the owner. It never retries that economic preparation.
    await tx.execute(sql`UPDATE oid_task_preparation_dispatch SET state='unknown',settled_at=clock_timestamp()
      WHERE preparation_id=${intent.preparationId} AND state='dispatching'`);
    await appendObservation(tx, {
      preparationId: intent.preparationId, status: 'fenced', generationId: observation.generationId,
      participantId: observation.participantId, payerAddress: observation.payerAddress,
      baselineStateSha256: observation.baselineStateSha256, fixtureEvidence: observation.fixtureEvidence,
      baselineEvidence: observation.baselineEvidence,
    });
    return { released: true, replayed: false };
  });
}

/** Persist adapter results only through the injected internal port; there is no HTTP route for it. */
async function prepareTaskExecutionFromBegun(deps: TaskPreparationDependencies, begun: { preparation: TaskPreparationRecord; replayed: boolean }): Promise<TaskPreparationRecord> {
  let record = begun.preparation;
  if (record.observation.status === 'ready' || record.observation.status === 'fenced') return record;
  if (record.observation.status === 'unknown' && !record.observation.generationId) return record;
  let dispatchId: string | null = null;
  if (record.observation.status === 'preparing') {
    const dispatch = await claimInitialDispatch(deps.db, record.intent.preparationId);
    record = dispatch.preparation;
    if (!dispatch.claimed || !dispatch.dispatchId) return record;
    dispatchId = dispatch.dispatchId;
  }
  if (record.observation.status === 'ready' || record.observation.status === 'fenced') return record;
  if (record.observation.status === 'unknown' && !record.observation.generationId) return record;
  let outcome: TaskPreparationAdapterOutcome;
  try {
    outcome = record.observation.status === 'unknown'
      ? await deps.preparationAdapter.reconcile({ intent: record.intent, generationId: record.observation.generationId! })
      : await deps.preparationAdapter.prepare({ intent: record.intent, dispatchId: dispatchId! });
  } catch {
    const unknown = await recordTaskPreparationUnknown(deps.db, {
      preparationId: record.intent.preparationId, leaseId: record.intent.leaseId, claimId: record.intent.claimId,
      generationId: record.observation.generationId, reasonCode: 'adapter_call_failed',
    });
    if (dispatchId) {
      await settleInitialDispatch(deps.db, { preparationId: record.intent.preparationId, dispatchId, state: 'unknown' });
      return (await getTaskPreparation(deps.db, record.intent.preparationId)) ?? unknown.preparation;
    }
    return unknown.preparation;
  }
  if (outcome.status === 'unknown') {
    const unknown = await recordTaskPreparationUnknown(deps.db, {
      preparationId: record.intent.preparationId, leaseId: record.intent.leaseId, claimId: record.intent.claimId,
      ...(outcome.generationId === undefined ? {} : { generationId: outcome.generationId }), reasonCode: outcome.reasonCode,
    });
    if (dispatchId) {
      await settleInitialDispatch(deps.db, { preparationId: record.intent.preparationId, dispatchId, state: 'unknown' });
      return (await getTaskPreparation(deps.db, record.intent.preparationId)) ?? unknown.preparation;
    }
    return unknown.preparation;
  }
  try {
    const ready = await recordTaskPreparationReady(deps.db, {
      preparationId: record.intent.preparationId, leaseId: record.intent.leaseId, claimId: record.intent.claimId,
      result: outcome.result,
    });
    if (dispatchId) {
      await settleInitialDispatch(deps.db, { preparationId: record.intent.preparationId, dispatchId, state: 'completed' });
      return (await getTaskPreparation(deps.db, record.intent.preparationId)) ?? ready.preparation;
    }
    return ready.preparation;
  } catch (error) {
    const originalGenerationId = record.observation.generationId ??
      (UUID.test(outcome.result.generationId) ? outcome.result.generationId : null);
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
    const reasonCode: PreparationUnknownReason = code === 'TASK_PREPARATION_RESULT_MISMATCH'
      ? (outcome.result.initialStateSha256?.toLowerCase() === record.intent.initialStateSha256 ? 'preparation_identity_mismatch' : 'baseline_state_mismatch')
      : 'preparation_identity_mismatch';
    const unknown = await recordTaskPreparationUnknown(deps.db, {
      preparationId: record.intent.preparationId, leaseId: record.intent.leaseId, claimId: record.intent.claimId,
      generationId: originalGenerationId, reasonCode,
    });
    if (dispatchId) {
      await settleInitialDispatch(deps.db, { preparationId: record.intent.preparationId, dispatchId, state: 'unknown' });
      return (await getTaskPreparation(deps.db, record.intent.preparationId)) ?? unknown.preparation;
    }
    return unknown.preparation;
  }
}

export async function prepareTaskExecution(deps: TaskPreparationDependencies, target: TaskPreparationTarget): Promise<TaskPreparationRecord> {
  target = normalizeTarget(target);
  if (target.taskIndex !== 0) fail(409, 'FIRST_TASK_PREPARATION_REQUIRED', 'Use the explicit successor execution-preparation API for later tasks');
  return prepareTaskExecutionFromBegun(deps, await beginTaskPreparationInternal(deps, target));
}

export async function prepareSuccessorTaskExecution(
  deps: SuccessorTaskPreparationDependencies,
  target: TaskPreparationTarget,
): Promise<TaskPreparationRecord> {
  target = normalizeTarget(target);
  if (target.taskIndex < 1) fail(400, 'INVALID_SUCCESSOR_TASK_INDEX', 'A successor task index must be at least one');
  const begun = await beginSuccessorTaskPreparation(deps, target);
  return prepareTaskExecutionFromBegun(deps, begun);
}

/** Adapter fence confirmations are the only path that can release a durable environment lease. */
export async function fenceTaskPreparation(
  deps: Pick<TaskPreparationDependencies, 'db' | 'preparationAdapter'>,
  preparationId: string,
  expectedGenerationId?: string | null,
): Promise<{ released: boolean; replayed: boolean }> {
  const result = await fenceTaskPreparationWithEvidence(deps, preparationId, expectedGenerationId);
  return { released: result.released, replayed: result.replayed };
}

export async function fenceTaskPreparationWithEvidence(
  deps: Pick<TaskPreparationDependencies, 'db' | 'preparationAdapter'>,
  preparationId: string,
  expectedGenerationId?: string | null,
): Promise<{ released: boolean; replayed: boolean; evidenceHash: string }> {
  const record = await getTaskPreparation(deps.db, preparationId);
  if (!record) fail(404, 'TASK_PREPARATION_NOT_FOUND', 'The task preparation does not exist');
  const generationId = expectedGenerationId === undefined ? record.observation.generationId : expectedGenerationId;
  if (record.observation.generationId !== generationId) {
    fail(409, 'TASK_ENVIRONMENT_FENCE_MISMATCH', 'The fence generation differs from the immutable cancellation target');
  }
  // A run cancellation may lose its process after the environment lease is
  // fenced but before the run cancellation transaction commits. Reuse the
  // exact stored fence proof on retry; do not ask the adapter to mint a new
  // receipt that could conflict with the immutable lease evidence.
  if (expectedGenerationId !== undefined && record.leaseStatus === 'fenced') {
    const stored = await storedTaskPreparationFenceEvidence(deps.db, record.intent, generationId);
    if (!stored) fail(409, 'TASK_ENVIRONMENT_FENCE_MISMATCH', 'The stored lease fence does not match this cancellation target');
    return { released: true, replayed: true, evidenceHash: stored };
  }
  const evidence = await deps.preparationAdapter.fence({ intent: record.intent, generationId });
  const result = await fenceAndReleaseTaskEnvironmentLease(deps.db, evidence);
  const parsedEvidence = parseEvidence(evidence.evidence);
  if (!parsedEvidence) fail(400, 'INVALID_TASK_ENVIRONMENT_FENCE', 'Fence evidence must be a hash-backed raw evidence reference');
  return { ...result, evidenceHash: parsedEvidence.sha256 };
}

async function storedTaskPreparationFenceEvidence(
  db: OwnerDatabase,
  intent: TaskPreparationIntentPins,
  generationId: string | null,
): Promise<string | null> {
  const rows = await db.execute(sql`SELECT state,fence_evidence FROM oid_task_environment_lease
    WHERE preparation_id=${intent.preparationId} AND lease_id=${intent.leaseId} AND environment_id=${intent.environmentId}`) as unknown as
      Array<{ state: string; fence_evidence: unknown }>;
  if (rows[0]?.state !== 'fenced') return null;
  const fence = asJson(rows[0].fence_evidence);
  if (!fence || typeof fence !== 'object' || Array.isArray(fence)) return null;
  const body = fence as Record<string, unknown>;
  const storedGeneration = typeof body.generationId === 'string' ? body.generationId.toLowerCase() : body.generationId;
  if (body.confirmed !== true || typeof body.preparationId !== 'string' || body.preparationId.toLowerCase() !== intent.preparationId ||
      typeof body.leaseId !== 'string' || body.leaseId.toLowerCase() !== intent.leaseId || body.environmentId !== intent.environmentId ||
      storedGeneration !== generationId) return null;
  return parseEvidence(body.evidence)?.sha256 ?? null;
}

export interface TaskPreparationSessionRevoker {
  unbindSession(runId: string, taskIndex: number): void;
}

/**
 * Bridges durable run cancellation to the exact preparation fence. The input
 * target is copied into the cancellation outbox while the run lock is held;
 * missing or changed identities fail closed and keep the run slot and holds.
 */
export function createTaskPreparationCancellationExecutor(
  deps: TaskPreparationDependencies,
  sessions: TaskPreparationSessionRevoker,
  options:{actionEvidenceSink?:TaskActionEvidenceSink}={},
): CancellationExecutor {
  return {
    async fenceAndStop(input) {
      const target = input.taskPreparation;
      if (!target || !UUID.test(target.preparationId) ||
          (target.generationId !== null && !UUID.test(target.generationId)) ||
          (target.taskIndex !== undefined && (!Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11))) return { fenced: false };
        const preparationId = target.preparationId.toLowerCase();
        const generationId = target.generationId?.toLowerCase() ?? null;
        const record = await getTaskPreparation(deps.db, preparationId);
      const expectedTaskIndex = target.taskIndex ?? 0;
        if (!record || record.intent.runId !== input.runId.toLowerCase() || record.intent.taskIndex !== expectedTaskIndex ||
            record.observation.generationId !== generationId) return { fenced: false };
        const fence = await fenceTaskPreparationWithEvidence(deps, preparationId, generationId);
      if (!fence.released) return { fenced: false };
      await finalizeFencedTaskActionReceipts({db:deps.db,...(options.actionEvidenceSink?{evidenceSink:options.actionEvidenceSink}:{})},{
        runId:input.runId.toLowerCase(),agentId:input.agentId.toLowerCase(),taskIndex:record.intent.taskIndex,
        preparationId,generationId,fenceEvidenceHash:fence.evidenceHash,
      });
        deps.preparationAdapter.clearCredentials?.(preparationId);
        sessions.unbindSession(input.runId.toLowerCase(), record.intent.taskIndex);
      return { fenced: true, evidenceHash: fence.evidenceHash, taskPreparation: {
          taskIndex: record.intent.taskIndex, preparationId, generationId,
      } };
    },
  };
}
