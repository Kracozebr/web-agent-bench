// Private local successor activation for admitted training and ranked runs.
//
// This module only advances an already charged, running run after the
// strict task finalizer proves that its predecessor is already terminal. It
// never scores, charges, refunds, or starts a real executor. The injected
// PreparedTaskStartPort is authoritative; callers must attach the returned
// secret-free preparation after commit and cancel/fence that exact generation
// if attachment fails. A committed activation must never be blindly retried
// after an attach failure.
import { createHash, randomUUID } from 'node:crypto';
import { sql, type SQL } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type TaskReleaseQuerySource,
  type ValidatedTaskReleaseRecord,
} from './task-release.js';
import { selectTaskIds } from './task-catalog.js';
import type { TaskMode } from './task-catalog.js';
import {
  getTaskExecutionBinding,
  getTaskExecutionContext,
  insertTaskExecutionBindingInTransaction,
  type PublicTaskExecutionBinding,
  type TaskExecutionBindingReader,
} from './task-execution-binding.js';
import {
  finalizeKnownRankedTask,
  finalizeKnownTrainingTask,
  type FinalizedTrainingTask,
  type TaskRunCompletionDependencies,
} from './task-run-completion.js';
import type {
  PreparedTaskStartPort,
  TaskPreparationRecord,
  TaskPreparationTarget,
  TaskPreparationTransaction,
} from './task-preparation.js';
import { readKnownCanonicalRankedEvaluation, readKnownCanonicalTrainingEvaluation } from './task-preparation.js';
import { readSuccessorPreparationPolicySnapshot } from './run-service.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const EVIDENCE_PATH = /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;

export interface TaskSuccessorActivationDependencies extends TaskRunCompletionDependencies {
  preparedTaskStart: PreparedTaskStartPort;
}

export type TaskSuccessorActivation = {
  runId: string;
  fromTaskIndex: number;
  toTaskIndex: number;
  fromTaskId: string;
  toTaskId: string;
  activatedAt: string;
  predecessorFinishedAt: string;
  preparationIntervalMilliseconds: number;
  previousOverallDeadline: string;
  overallDeadline: string;
  taskDeadline: string;
  successorPreparationPolicyVersion: string;
  successorPreparationTimeoutSeconds: number;
  replayed: boolean;
  // Internal backend value; never expose it in an owner or agent DTO. Null on replay.
  preparation: TaskPreparationRecord | null;
  binding: PublicTaskExecutionBinding;
};
export type TrainingSuccessorActivationDependencies = TaskSuccessorActivationDependencies;
export type TrainingSuccessorActivation = TaskSuccessorActivation;
export type RankedSuccessorActivation = TaskSuccessorActivation;

type RunRow = {
  id: string;
  intent_id: string;
  owner_id: string;
  agent_id: string;
  mode: string;
  task_ids: string[];
  release_identity: string;
  benchmark_version: string;
  manifest_hash: string;
  benchmark_hash: string;
  policy_hash: string;
  access_generation: number;
  agent_policy_revision: number;
  status: string;
  started_at: Date | string | null;
  overall_deadline: Date | string | null;
  finished_at: Date | string | null;
  terminal_reason: string | null;
  cancellation_reason: string | null;
  cancellation_requested_at: Date | string | null;
  environment_id: string | null;
  successor_preparation_policy_version: string | null;
  successor_preparation_timeout_seconds: number | null;
};

type TaskRow = {
  task_index: number;
  task_id: string;
  status: string;
  closure_status: string;
  closure_id: string | null;
  closure_operation_id: string | null;
  closure_payload_hash: string | null;
  closure_reason: string | null;
  accepted_action_sequence: string | number;
  action_cutoff_sequence: string | number | null;
  reconciled_action_sequence: string | number;
  closed_at: Date | string | null;
  started_at: Date | string | null;
  deadline_at: Date | string | null;
  finished_at: Date | string | null;
};

type Receipt = {
  runId: string;
  fromTaskIndex: number;
  toTaskIndex: number;
  taskId: string;
  status: 'completed' | 'failed';
  closureId: string;
  finishedAt: string;
  inputHash: string;
  resultHash: string;
  outcome: 'passed' | 'partial' | 'failed';
  preparationId: string;
  leaseId: string;
  generationId: string;
  fenceEvidenceHash: string;
};

function fail(status: number, code: string, message: string): never {
  throw new HttpError(status, code, message);
}

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('PostgreSQL returned an unexpected successor-activation result');
  return value as T[];
}

async function query<T>(reader: { execute(query: SQL): PromiseLike<unknown> }, statement: SQL): Promise<T[]> {
  return rows<T>(await reader.execute(statement));
}

function parsed(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function object(value: unknown): Record<string, unknown> | null {
  const valueObject = parsed(value);
  return valueObject && typeof valueObject === 'object' && !Array.isArray(valueObject)
    ? valueObject as Record<string, unknown> : null;
}

function date(value: Date | string | null): Date | null {
  if (value === null) return null;
  const result = value instanceof Date ? value : new Date(value);
  return Number.isFinite(result.getTime()) ? result : null;
}

function iso(value: Date | string | null): string | null {
  return date(value)?.toISOString() ?? null;
}

function safeHash(value: unknown): value is string {
  return typeof value === 'string' && HASH.test(value);
}

function safeEvidence(value: unknown): value is { path: string; sha256: string; boundary: string } {
  const item = object(value);
  return Boolean(item && typeof item.path === 'string' && EVIDENCE_PATH.test(item.path) &&
    safeHash(item.sha256) && item.boundary === 'actual_tool_http_x402_local_evm_application_store');
}

function same(left: unknown, right: unknown): boolean {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function hashRunServicePayload(value: unknown): string {
  const canonical = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonical);
    if (typeof item !== 'object' || item === null) return item;
    return Object.fromEntries(Object.entries(item as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, canonical(child)]));
  };
  return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

function isTaskMode(value: string): value is TaskMode { return value === 'training' || value === 'ranked'; }
function readKnownEvaluationForMode(result: unknown, input: unknown, taskId: string, runId: string, mode: string) {
  if (mode === 'training') return readKnownCanonicalTrainingEvaluation(result, input, taskId, runId);
  if (mode === 'ranked') return readKnownCanonicalRankedEvaluation(result, input, taskId, runId);
  return null;
}

function assertRunTaskOrder(run: RunRow, record: ValidatedTaskReleaseRecord, tasks: readonly TaskRow[]): void {
  if (!isTaskMode(run.mode)) fail(409, 'RUN_TASK_SELECTION_MISMATCH', 'The run mode is not supported for task successor activation');
  const selection = selectTaskIds(run.mode, run.task_ids);
  const releasedTaskIds: readonly string[] = record.manifest.cases[run.mode].map((taskCase) => taskCase.taskId);
  if (!selection.ok || selection.taskIds.some((taskId, index) => taskId !== run.task_ids[index]) ||
      tasks.length !== run.task_ids.length || tasks.some((task, index) =>
        task.task_index !== index || task.task_id !== run.task_ids[index] ||
        (index > 0 && releasedTaskIds.indexOf(task.task_id) <= releasedTaskIds.indexOf(tasks[index - 1]!.task_id)))) {
    fail(409, 'RUN_TASK_SELECTION_MISMATCH', 'The selected tasks do not match the pinned mode-specific release order');
  }
}

async function candidateFor(db: OwnerDatabase, runId: string): Promise<{ ownerId: string; agentId: string }> {
  const found = await query<{ owner_id: string; agent_id: string }>(db, sql`
    SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${runId}`);
  if (!found[0]) fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
  return { ownerId: found[0].owner_id, agentId: found[0].agent_id };
}

async function preflightKnownPredecessor(
  db: OwnerDatabase,
  runId: string,
  predecessorTaskIndex: number,
  expectedMode: TaskMode,
): Promise<{ taskIds: string[]; claimId: string }> {
  const targets = await query<{
    mode: string; status: string; task_ids: string[]; started_at: Date | string | null;
    overall_deadline: Date | string | null; cancellation_reason: string | null; cancellation_requested_at: Date | string | null;
  }>(db, sql`SELECT mode,status,task_ids,started_at,overall_deadline,cancellation_reason,cancellation_requested_at
    FROM oid_benchmark_run WHERE id=${runId}`);
  const run = targets[0];
  if (!run) fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
  if (run.mode !== expectedMode || run.status !== 'running' || !date(run.started_at) || !date(run.overall_deadline) ||
      run.cancellation_reason !== null || run.cancellation_requested_at !== null) {
    fail(409, 'SUCCESSOR_RUN_NOT_CURRENT', 'Only a current, running run of the selected mode can activate a successor');
  }
  const toTaskIndex = predecessorTaskIndex + 1;
  if (!Number.isSafeInteger(predecessorTaskIndex) || predecessorTaskIndex < 0 ||
      predecessorTaskIndex > 10 || toTaskIndex >= run.task_ids.length) {
    fail(409, 'SUCCESSOR_TASK_INDEX_INVALID', 'The selected task has no valid successor');
  }
  const taskRows = await query<TaskRow>(db, sql`SELECT task_index,task_id,status,closure_status,closure_id,closure_operation_id,
      closure_payload_hash,closure_reason,accepted_action_sequence::text AS accepted_action_sequence,
      action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
      closed_at,started_at,deadline_at,finished_at
    FROM oid_run_task WHERE run_id=${runId} ORDER BY task_index`);
  if (taskRows.length !== run.task_ids.length || taskRows.some((task, index) =>
      task.task_index !== index || task.task_id !== run.task_ids[index])) {
    fail(409, 'RUN_TASK_SET_INCOMPLETE', 'The run task rows do not match its immutable selection');
  }
  const predecessor = taskRows[predecessorTaskIndex];
  if (!predecessor || !['completed', 'failed'].includes(predecessor.status) || !date(predecessor.finished_at)) {
    fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'The predecessor must already have a known terminal receipt');
  }
  const events = await query<{ payload_json: unknown }>(db, sql`SELECT payload_json FROM oid_run_event
    WHERE run_id=${runId} AND event_type='task.activated' ORDER BY sequence`);
  const targetEvents = events.filter((event) => object(event.payload_json)?.toTaskIndex === toTaskIndex);
  if (targetEvents.length > 1) fail(409, 'SUCCESSOR_ACTIVATION_EVENT_MISMATCH', 'The successor has duplicate activation history');
  if (targetEvents.length === 0 &&
      (taskRows.some((task) => task.status === 'active') ||
       taskRows[toTaskIndex]?.status !== 'queued' || taskRows[toTaskIndex]?.started_at !== null ||
       taskRows[toTaskIndex]?.finished_at !== null ||
       taskRows.slice(toTaskIndex + 1).some((task) => task.status !== 'queued' || task.started_at !== null || task.finished_at !== null))) {
    fail(409, 'RUN_TASK_ORDER_CONFLICT', 'Only the exact queued next task may be activated');
  }
  const resultRows = await query<{ task_index: number; input_hash: string; result_hash: string; input_json: unknown; result_json: unknown }>(db, sql`SELECT task_index,input_hash,result_hash,input_json,result_json
    FROM oid_run_task_evaluation WHERE run_id=${runId} AND task_index<=${predecessorTaskIndex} ORDER BY task_index`);
  if (resultRows.length !== predecessorTaskIndex + 1 || resultRows.some((entry) => {
      const taskId = run.task_ids[entry.task_index];
      const known = taskId ? readKnownEvaluationForMode(entry.result_json, entry.input_json, taskId, runId, expectedMode) : null;
      return !Number.isSafeInteger(entry.task_index) || !taskId || !safeHash(entry.input_hash) || !safeHash(entry.result_hash) ||
        sha256CanonicalTaskJson(parsed(entry.input_json)) !== entry.input_hash ||
        sha256CanonicalTaskJson(parsed(entry.result_json)) !== entry.result_hash || !known ||
        (known.outcome === 'failed') !== (taskRows[entry.task_index]?.status === 'failed');
    })) {
    fail(409, 'RUN_TASK_EVALUATIONS_UNKNOWN', 'An unknown or contradictory result prevents successor activation');
  }
  const claimRows = await query<{ claim_id: string; status: string }>(db, sql`
    SELECT claim_id,status FROM oid_run_dispatch_claim WHERE run_id=${runId}`);
  if (!claimRows[0] || claimRows[0].status !== 'claimed' || !UUID.test(claimRows[0].claim_id)) {
    fail(409, 'STALE_RUN_CLAIM', 'The exact running dispatch claim is unavailable');
  }
  return { taskIds: run.task_ids, claimId: claimRows[0].claim_id };
}

async function assertNoCancellationHistory(tx: Transaction, run: RunRow): Promise<void> {
  if (run.cancellation_reason !== null || run.cancellation_requested_at !== null || run.finished_at !== null ||
      run.terminal_reason !== null) {
    fail(409, 'RUN_CANCELLATION_HISTORY', 'A cancelled or terminal run cannot activate another task');
  }
  const history = await query<{ revoked: boolean; mode_removed: boolean; receipt: boolean; pending_cancel: boolean }>(tx, sql`
    SELECT
      EXISTS(SELECT 1 FROM oid_agent_cancellation_outbox WHERE owner_id=${run.owner_id} AND agent_id=${run.agent_id}
        AND access_generation>${run.access_generation}) AS revoked,
      EXISTS(SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${run.owner_id} AND agent_id=${run.agent_id}
        AND mode=${run.mode} AND policy_revision>${run.agent_policy_revision}) AS mode_removed,
      EXISTS(SELECT 1 FROM oid_run_cancellation_receipt c
        WHERE ${run.id}=ANY(c.cancelled_run_ids) OR ${run.id}=ANY(c.pending_run_ids)) AS receipt,
      EXISTS(SELECT 1 FROM oid_run_outbox WHERE run_id=${run.id} AND event_type='run.cancel.requested') AS pending_cancel`);
  if (history[0]?.revoked || history[0]?.mode_removed || history[0]?.receipt || history[0]?.pending_cancel) {
    fail(409, 'RUN_CANCELLATION_HISTORY', 'A run with cancellation or access-revocation history cannot advance');
  }
}

async function validateRelease(tx: Transaction, run: RunRow, source: TaskReleaseQuerySource): Promise<ValidatedTaskReleaseRecord> {
  const record = await source.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
  if (!record || record.releaseIdentity !== run.release_identity || record.manifestHash !== run.manifest_hash ||
      record.benchmarkVersion !== run.benchmark_version || record.benchmarkHash !== run.benchmark_hash ||
      record.policyHash !== run.policy_hash || record.manifest.releaseIdentity !== run.release_identity ||
      record.manifest.manifestHash !== run.manifest_hash) {
    fail(503, 'PINNED_RELEASE_UNAVAILABLE', 'The exact validated release is unavailable');
  }
  return record;
}

function validatePolicy(run: RunRow, intentVersion: string | null, intentTimeout: number | null) {
  const policy = readSuccessorPreparationPolicySnapshot(
    run.successor_preparation_policy_version, run.successor_preparation_timeout_seconds,
  );
  const intentPolicy = readSuccessorPreparationPolicySnapshot(intentVersion, intentTimeout);
  if (!policy || !intentPolicy || policy.version !== intentPolicy.version ||
      policy.timeoutSeconds !== intentPolicy.timeoutSeconds) {
    fail(409, 'SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE', 'The immutable successor preparation policy snapshot is missing or inconsistent');
  }
  return policy;
}

async function validateActivationAccess(
  tx: Transaction,
  run: RunRow,
  ownerAdmissionStatus: string | undefined,
  agent: { access_generation: number; access_revoked_at: Date | string | null; training: boolean; ranked: boolean },
): Promise<void> {
  const modeAllowed = run.mode === 'training' ? agent.training : run.mode === 'ranked' ? agent.ranked : false;
  if (ownerAdmissionStatus !== 'admitted' || agent.access_revoked_at !== null ||
      agent.access_generation !== run.access_generation || !modeAllowed) {
    fail(409, 'RUN_ACCESS_NOT_CURRENT', 'Current owner and mode-specific agent access is required to activate a successor');
  }
  await assertNoCancellationHistory(tx, run);
}

async function validatePredecessorReceipt(
  tx: Transaction,
  run: RunRow,
  record: ValidatedTaskReleaseRecord,
  taskIndex: number,
  finalized: FinalizedTrainingTask,
): Promise<Receipt> {
  const found = await query<TaskRow>(tx, sql`SELECT task_index,task_id,status,closure_status,closure_id,closure_operation_id,
      closure_payload_hash,closure_reason,accepted_action_sequence::text AS accepted_action_sequence,
      action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
      closed_at,started_at,deadline_at,finished_at
    FROM oid_run_task WHERE run_id=${run.id} AND task_index=${taskIndex} FOR UPDATE`);
  const task = found[0];
  const finishedAt = iso(task?.finished_at ?? null);
  if (!task || task.task_id !== finalized.taskId || task.status !== finalized.status ||
      !['completed', 'failed'].includes(task.status) || task.closure_status !== 'closed' ||
      task.closure_id === null || task.closure_payload_hash === null || task.closure_reason === null ||
      !date(task.closed_at) || !finishedAt || finishedAt !== finalized.finishedAt ||
      task.action_cutoff_sequence === null ||
      BigInt(String(task.action_cutoff_sequence)) !== BigInt(String(task.accepted_action_sequence)) ||
      BigInt(String(task.action_cutoff_sequence)) !== BigInt(String(task.reconciled_action_sequence))) {
    fail(409, 'TASK_TERMINALIZATION_MISMATCH', 'The predecessor changed after strict terminal evidence replay');
  }
  if (!isTaskMode(run.mode)) fail(409, 'TASK_CASE_UNAVAILABLE', 'The run mode is not supported by its pinned release');
  const taskCase = record.manifest.cases[run.mode].find((entry) => entry.taskId === task.task_id);
  if (!taskCase) fail(409, 'TASK_CASE_UNAVAILABLE', 'The exact predecessor case is missing from the pinned release');

  const evaluations = await query<{
    run_id: string; task_index: number; closure_id: string; task_id: string; release_identity: string; manifest_hash: string;
    case_hash: string; rubric_hash: string; input_hash: string; result_hash: string; evaluator_source_hash: string;
    input_json: unknown; result_json: unknown;
  }>(tx, sql`SELECT run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,
      input_hash,result_hash,evaluator_source_hash,input_json,result_json
    FROM oid_run_task_evaluation WHERE run_id=${run.id} AND task_index=${taskIndex} FOR UPDATE`);
  const evaluation = evaluations[0];
  const input = parsed(evaluation?.input_json);
  const result = parsed(evaluation?.result_json);
  const known = evaluation ? readKnownEvaluationForMode(result, input, task.task_id, run.id, run.mode) : null;
  if (!evaluation || evaluation.run_id !== run.id || evaluation.task_index !== taskIndex ||
      evaluation.closure_id !== task.closure_id || evaluation.task_id !== task.task_id ||
      evaluation.release_identity !== run.release_identity || evaluation.manifest_hash !== run.manifest_hash ||
      evaluation.case_hash !== taskCase.caseHash || evaluation.rubric_hash !== taskCase.rubricHash ||
      !safeHash(evaluation.input_hash) || !safeHash(evaluation.result_hash) ||
      !safeHash(evaluation.evaluator_source_hash) || !input || !result ||
      sha256CanonicalTaskJson(input) !== evaluation.input_hash || sha256CanonicalTaskJson(result) !== evaluation.result_hash ||
      !known || (known.outcome === 'failed' ? 'failed' : 'completed') !== task.status) {
    fail(409, 'TASK_EVALUATION_BINDING_MISMATCH', 'The predecessor evaluation receipt or result hash changed');
  }

  const evaluationPayload = {
    taskIndex, taskId: task.task_id, closureId: task.closure_id, releaseIdentity: run.release_identity,
    manifestHash: run.manifest_hash, inputHash: evaluation.input_hash, resultHash: evaluation.result_hash,
    evaluatorSourceHash: evaluation.evaluator_source_hash,
  };
  const evaluationEvents = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`
    SELECT source,payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${run.id} AND event_type='task.evaluated' ORDER BY sequence`);
  const matchingEvaluationEvents = evaluationEvents.filter((event) => object(event.payload_json)?.taskIndex === taskIndex);
  if (matchingEvaluationEvents.length !== 1 || matchingEvaluationEvents[0]!.source !== 'coordinator' ||
      matchingEvaluationEvents[0]!.payload_hash !== sha256CanonicalTaskJson(evaluationPayload) ||
      !same(matchingEvaluationEvents[0]!.payload_json, evaluationPayload)) {
    fail(409, 'TASK_EVALUATION_EVENT_MISMATCH', 'The immutable predecessor evaluation event is missing or inconsistent');
  }

  const closureRows = await query<{
    action_cutoff_sequence: string | number; payload_hash: string; reason: string; operation_id: string | null;
  }>(tx, sql`SELECT action_cutoff_sequence::text AS action_cutoff_sequence,payload_hash,reason,operation_id
    FROM oid_run_task_closure WHERE id=${task.closure_id} AND run_id=${run.id} AND task_index=${taskIndex} FOR UPDATE`);
  const closure = closureRows[0];
  if (!closure || closure.payload_hash !== task.closure_payload_hash || closure.reason !== task.closure_reason ||
      closure.operation_id !== task.closure_operation_id ||
      BigInt(String(closure.action_cutoff_sequence)) !== BigInt(String(task.action_cutoff_sequence))) {
    fail(409, 'TASK_CLOSURE_MISMATCH', 'The predecessor closure receipt differs from its immutable cutoff');
  }
  const actionRows = await query<{ action_sequence: string; receipt_status: string | null; outbox_status: string | null }>(tx, sql`
    SELECT a.action_sequence::text AS action_sequence,r.receipt_status,o.status AS outbox_status
    FROM oid_run_task_action a
    LEFT JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN oid_run_task_action_outbox o ON o.action_id=a.id
    WHERE a.run_id=${run.id} AND a.task_index=${taskIndex} ORDER BY a.action_sequence FOR UPDATE OF a`);
  const cutoff = BigInt(String(task.action_cutoff_sequence));
  if (BigInt(actionRows.length) !== cutoff || actionRows.some((action, index) =>
      BigInt(action.action_sequence) !== BigInt(index + 1) ||
      !['observed', 'rejected_before_execution'].includes(String(action.receipt_status)) ||
      action.outbox_status !== 'delivered')) {
    fail(409, 'TASK_ACTIONS_NOT_RECONCILED', 'The predecessor cutoff receipts are no longer fully reconciled');
  }

  const bundleRows = await query<{ bundle_hash: string; bundle_json: unknown; generation_id: string; preparation_id: string;
    lease_id: string; environment_id: string; environment_manifest_hash: string; application_source_hash: string;
    execution_identity_hash: string; initial_state_sha256: string; closure_id: string; closure_payload_hash: string;
    action_cutoff_sequence: string; reconciled_action_sequence: string; cutoff_evidence: unknown;
  }>(tx, sql`SELECT bundle_hash,bundle_json,generation_id,preparation_id,lease_id,environment_id,
      environment_manifest_hash,application_source_hash,execution_identity_hash,initial_state_sha256,closure_id,
      closure_payload_hash,action_cutoff_sequence::text AS action_cutoff_sequence,
      reconciled_action_sequence::text AS reconciled_action_sequence,cutoff_evidence
    FROM oid_run_task_observation_bundle WHERE run_id=${run.id} AND task_index=${taskIndex} FOR UPDATE`);
  const bundle = bundleRows[0];
  const bundleJson = object(bundle?.bundle_json);
  const execution = object(bundleJson?.execution);
  const context = await getTaskExecutionContext(tx, { runId: run.id, taskIndex }, { requireActive: false });
  const taskIdentity = record.manifest.executionIdentity;
  if (!bundle || !bundleJson || !execution || !context || bundle.bundle_hash !== sha256CanonicalTaskJson(bundleJson) ||
      bundle.closure_id !== task.closure_id || bundle.closure_payload_hash !== task.closure_payload_hash ||
      BigInt(bundle.action_cutoff_sequence) !== cutoff ||
      BigInt(bundle.reconciled_action_sequence) !== BigInt(String(task.reconciled_action_sequence)) ||
      execution.preparationId !== context.preparationId || execution.leaseId !== context.leaseId ||
      execution.generationId !== context.generationId ||
      bundle.preparation_id !== context.preparationId || bundle.lease_id !== context.leaseId ||
      bundle.generation_id !== context.generationId || bundle.environment_id !== context.envId ||
      bundle.environment_manifest_hash !== context.environmentManifestSha256 ||
      bundle.application_source_hash !== context.applicationSourceHash ||
      bundle.execution_identity_hash !== context.executionIdentityHash ||
      bundle.initial_state_sha256 !== context.initialStateSha256 ||
      context.runId !== run.id || context.taskIndex !== taskIndex || context.taskId !== task.task_id ||
      context.mode !== run.mode || context.releaseIdentity !== run.release_identity ||
      context.releaseManifestHash !== run.manifest_hash || context.caseId !== taskCase.caseId ||
      context.caseHash !== taskCase.caseHash || context.initialStateSha256 !== taskCase.initialState.stateSha256 ||
      context.executionIdentityHash !== taskCase.executionIdentityHash ||
      context.environmentManifestSha256 !== taskIdentity.environmentManifestSha256 ||
      context.applicationSourceHash !== taskIdentity.x402ServiceSha256 || !context.hasExecutionBinding) {
    fail(409, 'TASK_OBSERVATION_BUNDLE_MISMATCH', 'The predecessor bundle and execution pins changed after evidence replay');
  }
  const fenceRows = await query<{ lease_state: string; fence_evidence: unknown; observation_status: string;
    generation_id: string | null; baseline_state_sha256: string | null; registered_generation_id: string | null;
    generation_environment_id: string | null;
  }>(tx, sql`SELECT l.state AS lease_state,l.fence_evidence,o.status AS observation_status,o.generation_id,
      o.baseline_state_sha256,g.generation_id AS registered_generation_id,g.environment_id AS generation_environment_id
    FROM oid_task_environment_lease l
    JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256 FROM oid_task_preparation_observation
      WHERE preparation_id=l.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    LEFT JOIN oid_task_preparation_generation g ON g.preparation_id=l.preparation_id
    WHERE l.preparation_id=${context.preparationId} AND l.lease_id=${context.leaseId} FOR UPDATE OF l`);
  const fenceRow = fenceRows[0];
  const fence = object(fenceRow?.fence_evidence);
  const fenceEvidence = object(fence?.evidence);
  if (!fenceRow || fenceRow.lease_state !== 'fenced' || fenceRow.observation_status !== 'fenced' ||
      fenceRow.generation_id !== context.generationId || fenceRow.registered_generation_id !== context.generationId ||
      fenceRow.generation_environment_id !== context.envId || fenceRow.baseline_state_sha256 !== context.initialStateSha256 ||
      fence?.confirmed !== true || fence?.preparationId !== context.preparationId || fence?.leaseId !== context.leaseId ||
      fence?.environmentId !== context.envId || fence?.generationId !== context.generationId ||
      !safeEvidence(fenceEvidence)) {
    fail(409, 'TASK_ORIGINAL_GENERATION_NOT_FENCED', 'The exact predecessor generation fence is no longer verifiable');
  }
  const fenceEvidenceHash = fenceEvidence.sha256 as string;
  const terminalPayload = {
    runId: run.id, taskIndex, taskId: task.task_id, closureId: task.closure_id,
    releaseIdentity: run.release_identity, manifestHash: run.manifest_hash,
    inputHash: evaluation.input_hash, resultHash: evaluation.result_hash,
    outcome: known.outcome, status: known.outcome === 'failed' ? 'failed' : 'completed', finishedAt,
    preparationId: context.preparationId, leaseId: context.leaseId,
    generationId: context.generationId, fenceEvidenceHash,
  };
  const terminalEvents = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`
    SELECT source,payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${run.id} AND event_type='task.terminalized' ORDER BY sequence`);
  const matchingTerminalEvents = terminalEvents.filter((event) => object(event.payload_json)?.taskIndex === taskIndex);
  if (matchingTerminalEvents.length !== 1 || matchingTerminalEvents[0]!.source !== 'coordinator' ||
      matchingTerminalEvents[0]!.payload_hash !== sha256CanonicalTaskJson(terminalPayload) ||
      !same(matchingTerminalEvents[0]!.payload_json, terminalPayload)) {
    fail(409, 'TASK_TERMINALIZATION_EVENT_MISMATCH', 'The exact predecessor terminalization event is missing or inconsistent');
  }
  return {
    runId: run.id, fromTaskIndex: taskIndex, toTaskIndex: taskIndex + 1, taskId: task.task_id,
    status: known.outcome === 'failed' ? 'failed' : 'completed', closureId: task.closure_id, finishedAt,
    inputHash: evaluation.input_hash, resultHash: evaluation.result_hash, outcome: known.outcome,
    preparationId: context.preparationId, leaseId: context.leaseId, generationId: context.generationId,
    fenceEvidenceHash,
  };
}

async function validatePreviousDeadlineEvent(
  tx: Transaction,
  run: RunRow,
  fromTaskIndex: number,
  oldOverallDeadline: string,
): Promise<void> {
  if (fromTaskIndex === 0) {
    const events = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`
      SELECT source,payload_hash,payload_json FROM oid_run_event
      WHERE run_id=${run.id} AND event_type='run.started' ORDER BY sequence`);
    const payload = object(events[0]?.payload_json);
    const firstTask = await query<{ deadline_at: Date | string | null }>(tx, sql`
      SELECT deadline_at FROM oid_run_task WHERE run_id=${run.id} AND task_index=0`);
    const firstContext = await getTaskExecutionContext(tx, { runId: run.id, taskIndex: 0 }, { requireActive: false });
    const expectedShape = payload ? {
      startedAt: payload.startedAt, taskId: payload.taskId, taskDeadline: payload.taskDeadline,
      overallDeadline: payload.overallDeadline, environmentId: payload.environmentId,
      readinessEvidenceHash: payload.readinessEvidenceHash,
    } : null;
    if (events.length !== 1 || events[0]!.source !== 'coordinator' || !payload || !expectedShape ||
        events[0]!.payload_hash !== hashRunServicePayload(expectedShape) ||
        payload.startedAt !== iso(run.started_at) || payload.overallDeadline !== oldOverallDeadline ||
        payload.taskId !== run.task_ids[0] || payload.taskDeadline !== iso(firstTask[0]?.deadline_at ?? null) ||
        !firstContext || payload.environmentId !== firstContext.envId ||
        payload.readinessEvidenceHash !== firstContext.environmentEvidenceHash) {
      fail(409, 'SUCCESSOR_DEADLINE_CHAIN_MISMATCH', 'The original run deadline event does not match the successor clock');
    }
    return;
  }
  const events = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`
    SELECT source,payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${run.id} AND event_type='task.activated' ORDER BY sequence`);
  const previous = events.filter((event) => object(event.payload_json)?.toTaskIndex === fromTaskIndex);
  const payload = object(previous[0]?.payload_json);
  const priorTask = await query<{ started_at: Date | string | null; deadline_at: Date | string | null }>(tx, sql`
    SELECT started_at,deadline_at FROM oid_run_task WHERE run_id=${run.id} AND task_index=${fromTaskIndex}`);
  const binding = await getTaskExecutionBinding(tx, { runId: run.id, taskIndex: fromTaskIndex });
  const context = await getTaskExecutionContext(tx, { runId: run.id, taskIndex: fromTaskIndex }, { requireActive: false });
  const prep = object(payload?.preparation);
  if (previous.length !== 1 || previous[0]!.source !== 'coordinator' || !payload ||
      previous[0]!.payload_hash !== sha256CanonicalTaskJson(payload) ||
      payload.toTaskIndex !== fromTaskIndex || payload.toTaskId !== run.task_ids[fromTaskIndex] ||
      payload.overallDeadline !== oldOverallDeadline ||
      payload.activatedAt !== iso(priorTask[0]?.started_at ?? null) ||
      payload.taskDeadline !== iso(priorTask[0]?.deadline_at ?? null) ||
      !binding || !context || !same(payload.binding, binding) ||
      prep?.preparationId !== context.preparationId || prep?.generationId !== context.generationId) {
    fail(409, 'SUCCESSOR_DEADLINE_CHAIN_MISMATCH', 'The preceding task activation does not bind the current run deadline');
  }
}

function eventBinding(value: unknown): PublicTaskExecutionBinding | null {
  const item = object(value);
  if (!item || typeof item.runId !== 'string' || !UUID.test(item.runId) ||
      !Number.isSafeInteger(item.taskIndex) || typeof item.envId !== 'string' ||
      typeof item.generationId !== 'string' || !UUID.test(item.generationId) ||
      typeof item.manifestHash !== 'string' || !safeHash(item.manifestHash) ||
      typeof item.applicationSourceHash !== 'string' || !safeHash(item.applicationSourceHash) ||
      !(item.participantId === null || typeof item.participantId === 'string') ||
      !(item.payerAddress === null || typeof item.payerAddress === 'string') ||
      typeof item.createdAt !== 'string' || !date(item.createdAt)) return null;
  return item as unknown as PublicTaskExecutionBinding;
}

async function replayActivation(
  tx: Transaction,
  run: RunRow,
  record: ValidatedTaskReleaseRecord,
  tasks: readonly TaskRow[],
  toTaskIndex: number,
  receipt: Receipt,
  policyVersion: string,
  policyTimeoutSeconds: number,
  events: Array<{ source: string; payload_hash: string; payload_json: unknown }>,
): Promise<TaskSuccessorActivation | null> {
  const matches = events.filter((event) => object(event.payload_json)?.toTaskIndex === toTaskIndex);
  if (matches.length === 0) return null;
  if (matches.length !== 1 || matches[0]!.source !== 'coordinator') {
    fail(409, 'SUCCESSOR_ACTIVATION_EVENT_MISMATCH', 'The successor activation journal is duplicated or has an unexpected source');
  }
  const event = matches[0]!;
  const payload = object(event.payload_json);
  const task = tasks[toTaskIndex];
  if (!payload || !task || event.payload_hash !== sha256CanonicalTaskJson(payload) ||
      task.task_id !== run.task_ids[toTaskIndex] || !['active', 'completed', 'failed'].includes(task.status) ||
      !date(task.started_at) || iso(task.started_at) !== payload.activatedAt ||
      (task.status === 'active' && (!['open', 'closing', 'closed'].includes(task.closure_status) || date(task.finished_at))) ||
      (task.status !== 'active' && (!['completed', 'failed'].includes(task.status) || !date(task.finished_at)))) {
    fail(409, 'SUCCESSOR_ACTIVATION_EVENT_MISMATCH', 'The successor task state does not match its activation event');
  }
  const activatedAt = typeof payload.activatedAt === 'string' ? date(payload.activatedAt) : null;
  const finishedAt = date(receipt.finishedAt);
  const oldDeadline = typeof payload.previousOverallDeadline === 'string' ? date(payload.previousOverallDeadline) : null;
  const newDeadline = typeof payload.overallDeadline === 'string' ? date(payload.overallDeadline) : null;
  const taskDeadline = typeof payload.taskDeadline === 'string' ? date(payload.taskDeadline) : null;
  const interval = payload.preparationIntervalMilliseconds;
  const duration = isTaskMode(run.mode)
    ? record.manifest.cases[run.mode].find((entry) => entry.taskId === task.task_id)?.taskDeadlineSeconds
    : undefined;
  const expectedPredecessorReceipt = {
    closureId: receipt.closureId, inputHash: receipt.inputHash, resultHash: receipt.resultHash,
    outcome: receipt.outcome, preparationId: receipt.preparationId, leaseId: receipt.leaseId,
    generationId: receipt.generationId, fenceEvidenceHash: receipt.fenceEvidenceHash,
  };
  if (!activatedAt || !finishedAt || !oldDeadline || !newDeadline || !taskDeadline ||
      !Number.isSafeInteger(interval) || (interval as number) < 0 ||
      payload.runId !== run.id || payload.fromTaskIndex !== toTaskIndex - 1 ||
      payload.fromTaskId !== run.task_ids[toTaskIndex - 1] || payload.toTaskId !== task.task_id ||
      payload.predecessorFinishedAt !== receipt.finishedAt ||
      !same(payload.predecessorReceipt, expectedPredecessorReceipt) ||
      payload.successorPreparationPolicyVersion !== policyVersion ||
      payload.successorPreparationTimeoutSeconds !== policyTimeoutSeconds ||
      interval !== activatedAt.getTime() - finishedAt.getTime() ||
      activatedAt.getTime() < finishedAt.getTime() ||
      activatedAt.getTime() - finishedAt.getTime() > policyTimeoutSeconds * 1000 ||
      finishedAt.getTime() >= oldDeadline.getTime() ||
      newDeadline.getTime() !== oldDeadline.getTime() + (interval as number) ||
      typeof duration !== 'number' ||
      taskDeadline.getTime() !== Math.min(activatedAt.getTime() + duration * 1000, newDeadline.getTime()) ||
      iso(task.deadline_at) !== taskDeadline.toISOString()) {
    fail(409, 'SUCCESSOR_ACTIVATION_EVENT_MISMATCH', 'The activation clock fields do not match the pinned preparation policy');
  }
  await validatePreviousDeadlineEvent(tx, run, toTaskIndex - 1, oldDeadline.toISOString());
  const bindingFromEvent = eventBinding(payload.binding);
  const actualBinding = await getTaskExecutionBinding(tx, { runId: run.id, taskIndex: toTaskIndex });
  const context = await getTaskExecutionContext(tx, { runId: run.id, taskIndex: toTaskIndex }, { requireActive: false });
  const preparation = object(payload.preparation);
  if (!bindingFromEvent || !actualBinding || !context ||
      !same(bindingFromEvent, actualBinding) || actualBinding.runId !== run.id || actualBinding.taskIndex !== toTaskIndex ||
      actualBinding.envId !== context.envId || actualBinding.generationId !== context.generationId ||
      actualBinding.manifestHash !== context.environmentManifestSha256 ||
      actualBinding.applicationSourceHash !== context.applicationSourceHash ||
      actualBinding.participantId !== context.participantId || actualBinding.payerAddress !== context.payerAddress ||
      !preparation || preparation.preparationId !== context.preparationId ||
      preparation.leaseId !== context.leaseId || preparation.environmentId !== context.envId ||
      preparation.generationId !== context.generationId ||
      preparation.environmentManifestSha256 !== context.environmentManifestSha256 ||
      preparation.applicationSourceHash !== context.applicationSourceHash ||
      preparation.environmentEvidenceHash !== context.environmentEvidenceHash) {
    fail(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The replayed binding does not match the immutable prepared generation');
  }
  return {
    runId: run.id, fromTaskIndex: toTaskIndex - 1, toTaskIndex,
    fromTaskId: receipt.taskId, toTaskId: task.task_id,
    activatedAt: activatedAt.toISOString(), predecessorFinishedAt: finishedAt.toISOString(),
    preparationIntervalMilliseconds: interval as number,
    previousOverallDeadline: oldDeadline.toISOString(), overallDeadline: newDeadline.toISOString(),
    taskDeadline: taskDeadline.toISOString(),
    successorPreparationPolicyVersion: policyVersion,
    successorPreparationTimeoutSeconds: policyTimeoutSeconds,
    replayed: true, preparation: null, binding: actualBinding,
  };
}

function validatePreparedPins(
  preparation: TaskPreparationRecord,
  run: RunRow,
  record: ValidatedTaskReleaseRecord,
  target: TaskPreparationTarget,
  taskId: string,
  claimId: string,
): void {
  const taskCase = isTaskMode(run.mode) ? record.manifest.cases[run.mode].find((entry) => entry.taskId === taskId) : undefined;
  if (!taskCase || !UUID.test(preparation.intent.preparationId) ||
      preparation.intent.runId !== run.id || preparation.intent.taskIndex !== target.taskIndex ||
      preparation.intent.claimId !== claimId || preparation.intent.taskId !== taskId ||
      preparation.intent.releaseIdentity !== run.release_identity || preparation.intent.manifestHash !== run.manifest_hash ||
      preparation.intent.caseId !== taskCase.caseId || preparation.intent.caseHash !== taskCase.caseHash ||
      preparation.intent.initialStateSha256 !== taskCase.initialState.stateSha256 ||
      preparation.intent.executionIdentityHash !== taskCase.executionIdentityHash ||
      preparation.intent.environmentManifestSha256 !== record.manifest.executionIdentity.environmentManifestSha256 ||
      preparation.intent.applicationSourceHash !== record.manifest.executionIdentity.x402ServiceSha256 ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(preparation.intent.environmentId)) {
    fail(409, 'TASK_PREPARATION_PIN_MISMATCH', 'The prepared successor does not match its exact sealed release, claim, and baseline');
  }
  if (preparation.leaseStatus !== 'leased' || preparation.dispatchStatus !== 'completed' ||
      preparation.observation.status !== 'ready' || !preparation.observation.generationId ||
      !UUID.test(preparation.observation.generationId) ||
      preparation.observation.baselineStateSha256 !== preparation.intent.initialStateSha256 ||
      !safeEvidence(preparation.observation.fixtureEvidence) || !safeEvidence(preparation.observation.baselineEvidence)) {
    fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact successor generation must be ready, leased, dispatched, and baseline-verified');
  }
}

async function activatePreparedSuccessorForMode(
  deps: TaskSuccessorActivationDependencies,
  input: { runId: string; predecessorTaskIndex: number },
  mode: TaskMode,
): Promise<TaskSuccessorActivation> {
  if (!UUID.test(input.runId) || !Number.isSafeInteger(input.predecessorTaskIndex) ||
      input.predecessorTaskIndex < 0 || input.predecessorTaskIndex > 10) {
    fail(400, 'INVALID_SUCCESSOR_ACTIVATION_TARGET', 'A run UUID and bounded non-final predecessor index are required');
  }
  const runId = input.runId.toLowerCase();
  const predecessorTaskIndex = input.predecessorTaskIndex;

  // Read-only guards prevent accidentally terminalizing an active task.
  const preflight = await preflightKnownPredecessor(deps.db, runId, predecessorTaskIndex, mode);
  const finalize = mode === 'ranked' ? finalizeKnownRankedTask : finalizeKnownTrainingTask;
  const finalized = await finalize(deps, { runId, taskIndex: predecessorTaskIndex });
  if (!finalized.replayed) {
    fail(409, 'TASK_TERMINALIZATION_NOT_REPLAYED', 'Successor activation requires an already committed predecessor receipt');
  }
  const candidate = await candidateFor(deps.db, runId);
  const target: TaskPreparationTarget = {
    runId, taskIndex: predecessorTaskIndex + 1, claimId: preflight.claimId,
  };
  const candidatePreparationId = await deps.preparedTaskStart.readCandidatePreparationId(target);

  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${candidate.ownerId} FOR NO KEY UPDATE`);
    const agentRows = await query<{
      id: string; owner_id: string; access_generation: number; access_revoked_at: Date | string | null;
    }>(tx, sql`SELECT id,owner_id,access_generation,access_revoked_at FROM oid_agent
      WHERE id=${candidate.agentId} AND owner_id=${candidate.ownerId} FOR NO KEY UPDATE`);
    const policyRows = await query<{ training: boolean; ranked: boolean; revision: number }>(tx, sql`SELECT training,ranked,revision
      FROM oid_agent_policy WHERE agent_id=${candidate.agentId} FOR UPDATE`);
    const runRows = await query<RunRow & { owner_admission_status: string; intent_policy_version: string | null;
      intent_policy_timeout_seconds: number | null }>(tx, sql`SELECT r.id,r.intent_id,r.owner_id,r.agent_id,r.mode,r.task_ids,
        r.release_identity,r.benchmark_version,r.manifest_hash,r.benchmark_hash,r.policy_hash,r.access_generation,
        r.agent_policy_revision,r.status,r.started_at,r.overall_deadline,r.finished_at,r.terminal_reason,
        r.cancellation_reason,r.cancellation_requested_at,r.environment_id,
        r.successor_preparation_policy_version,r.successor_preparation_timeout_seconds,
        o.admission_status AS owner_admission_status,
        i.successor_preparation_policy_version AS intent_policy_version,
        i.successor_preparation_timeout_seconds AS intent_policy_timeout_seconds
      FROM oid_benchmark_run r
      JOIN oid_owner o ON o.id=r.owner_id
      JOIN oid_run_launch_intent i ON i.id=r.intent_id
      WHERE r.id=${runId} AND r.owner_id=${candidate.ownerId} AND r.agent_id=${candidate.agentId} FOR UPDATE OF r`);
    const run = runRows[0];
    const agent = agentRows[0];
    const agentPolicy = policyRows[0];
    if (!run || !agent || !agentPolicy) fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
    if (run.mode !== mode || run.status !== 'running' || !date(run.started_at) ||
        !date(run.overall_deadline) || run.finished_at !== null || run.terminal_reason !== null) {
      fail(409, 'SUCCESSOR_RUN_NOT_CURRENT', 'Only a current, running run of the selected mode can activate a successor');
    }
    await validateActivationAccess(tx, run, run.owner_admission_status, {
      access_generation: agent.access_generation, access_revoked_at: agent.access_revoked_at,
      training: agentPolicy.training, ranked: agentPolicy.ranked,
    });
    const runPolicy = validatePolicy(run, runRows[0]!.intent_policy_version, runRows[0]!.intent_policy_timeout_seconds);

    const claimRows = await query<{ claim_id: string; owner_id: string; agent_id: string; status: string }>(tx, sql`
      SELECT claim_id,owner_id,agent_id,status FROM oid_run_dispatch_claim WHERE run_id=${run.id} FOR UPDATE`);
    const claim = claimRows[0];
    const slotRows = await query<{ claim_id: string; owner_id: string; agent_id: string; state: string; released_at: Date | string | null }>(tx, sql`
      SELECT claim_id,owner_id,agent_id,state,released_at FROM oid_run_execution_slot
      WHERE run_id=${run.id} AND agent_id=${run.agent_id} FOR UPDATE`);
    const slot = slotRows[0];
    if (!claim || claim.owner_id !== run.owner_id || claim.agent_id !== run.agent_id || claim.status !== 'claimed' ||
        claim.claim_id !== preflight.claimId || !slot || slot.owner_id !== run.owner_id || slot.agent_id !== run.agent_id ||
        slot.claim_id !== claim.claim_id || slot.state !== 'running' || slot.released_at !== null) {
      fail(409, 'STALE_RUN_CLAIM', 'The original running claim and exclusive execution slot are required');
    }

    const record = await validateRelease(tx, run, deps.taskReleaseSource);
    const taskRows = await query<TaskRow>(tx, sql`SELECT task_index,task_id,status,closure_status,closure_id,closure_operation_id,
        closure_payload_hash,closure_reason,accepted_action_sequence::text AS accepted_action_sequence,
        action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
        closed_at,started_at,deadline_at,finished_at
      FROM oid_run_task WHERE run_id=${run.id} ORDER BY task_index FOR UPDATE`);
    assertRunTaskOrder(run, record, taskRows);
    const persistedPredecessor = taskRows[predecessorTaskIndex];
    const persistedSuccessor = taskRows[predecessorTaskIndex + 1];
    if (!persistedPredecessor || !persistedSuccessor ||
        !['completed', 'failed'].includes(persistedPredecessor.status) ||
        !date(persistedPredecessor.finished_at) ||
        persistedSuccessor.task_id !== run.task_ids[predecessorTaskIndex + 1]) {
      fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'The exact known predecessor and selected successor are required');
    }
    const activationEvents = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`
      SELECT source,payload_hash,payload_json FROM oid_run_event
      WHERE run_id=${run.id} AND event_type='task.activated' ORDER BY sequence`);
    const receipt = await validatePredecessorReceipt(tx, run, record, predecessorTaskIndex, finalized);
    const replay = await replayActivation(tx, run, record, taskRows, predecessorTaskIndex + 1,
      receipt, runPolicy.version, runPolicy.timeoutSeconds, activationEvents);
    if (replay) return replay;

    if (candidatePreparationId === null) {
      fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact selected successor has no durable preparation identity');
    }
    if (preflight.taskIds[predecessorTaskIndex + 1] !== persistedSuccessor.task_id ||
        persistedSuccessor.status !== 'queued' || persistedSuccessor.closure_status !== 'open' ||
        persistedSuccessor.started_at !== null || persistedSuccessor.finished_at !== null ||
        taskRows.some((task) => task.status === 'active') ||
        taskRows.slice(predecessorTaskIndex + 2).some((task) => task.status !== 'queued' ||
          task.started_at !== null || task.finished_at !== null)) {
      fail(409, 'RUN_TASK_ORDER_CONFLICT', 'Only the exact queued next task may be activated');
    }
    for (let index = 0; index < predecessorTaskIndex; index += 1) {
      if (!['completed', 'failed'].includes(taskRows[index]!.status) || !date(taskRows[index]!.finished_at)) {
        fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'Every earlier selected task must have a known terminal result');
      }
    }
    const results = await query<{ task_index: number; input_hash: string; result_hash: string; input_json: unknown; result_json: unknown }>(tx, sql`SELECT task_index,input_hash,result_hash,input_json,result_json
      FROM oid_run_task_evaluation WHERE run_id=${run.id} AND task_index<=${predecessorTaskIndex} ORDER BY task_index FOR UPDATE`);
    if (results.length !== predecessorTaskIndex + 1 || results.some((item) => {
        const taskId = run.task_ids[item.task_index];
        const known = taskId ? readKnownEvaluationForMode(item.result_json, item.input_json, taskId, run.id, mode) : null;
        return !Number.isSafeInteger(item.task_index) || !taskId || !safeHash(item.input_hash) || !safeHash(item.result_hash) ||
          sha256CanonicalTaskJson(parsed(item.input_json)) !== item.input_hash ||
          sha256CanonicalTaskJson(parsed(item.result_json)) !== item.result_hash || !known ||
          (known.outcome === 'failed') !== (taskRows[item.task_index]?.status === 'failed');
      })) {
      fail(409, 'RUN_TASK_EVALUATIONS_UNKNOWN', 'An unknown or contradictory result prevents successor activation');
    }

    const oldDeadline = date(run.overall_deadline);
    const predecessorFinishedAt = date(receipt.finishedAt);
    const taskCase = record.manifest.cases[mode].find((entry) => entry.taskId === persistedSuccessor.task_id);
    const taskTimeoutSeconds = taskCase?.taskDeadlineSeconds;
    if (!oldDeadline || !predecessorFinishedAt || !Number.isSafeInteger(taskTimeoutSeconds) ||
        (taskTimeoutSeconds ?? 0) < 1 || predecessorFinishedAt.getTime() >= oldDeadline.getTime()) {
      fail(409, 'SUCCESSOR_OVERALL_TIME_EXHAUSTED', 'The predecessor exhausted the original run deadline');
    }
    // This preliminary clock gives the readiness port a conservative session bound.
    // A second timestamp after all external readiness/lease waits controls the committed interval.
    const preliminaryNowRows = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
    const preliminaryActivationDate = date(preliminaryNowRows[0]?.now ?? null);
    if (!preliminaryActivationDate || preliminaryActivationDate.getTime() < predecessorFinishedAt.getTime()) {
      fail(409, 'SUCCESSOR_ACTIVATION_CLOCK_INVALID', 'The database activation timestamp precedes the known predecessor receipt');
    }
    const preliminaryInterval = preliminaryActivationDate.getTime() - predecessorFinishedAt.getTime();
    if (preliminaryInterval < 0 || preliminaryInterval > runPolicy.timeoutSeconds * 1000) {
      fail(409, 'SUCCESSOR_PREPARATION_TIMEOUT', 'The persisted successor preparation interval exceeded its immutable bound');
    }
    const oldDeadlineIso = oldDeadline.toISOString();
    await validatePreviousDeadlineEvent(tx, run, predecessorTaskIndex, oldDeadlineIso);
    const preliminaryNewDeadline = new Date(oldDeadline.getTime() + preliminaryInterval);
    const preliminaryTaskDeadline = new Date(Math.min(
      preliminaryActivationDate.getTime() + taskTimeoutSeconds! * 1000, preliminaryNewDeadline.getTime(),
    ));
    if (preliminaryTaskDeadline.getTime() <= preliminaryActivationDate.getTime()) {
      fail(409, 'SUCCESSOR_OVERALL_TIME_EXHAUSTED', 'No execution time remains for the selected successor');
    }
    const preliminaryMinimumValidUntil = preliminaryTaskDeadline.toISOString();
    const target: TaskPreparationTarget = { runId, taskIndex: predecessorTaskIndex + 1, claimId: claim.claim_id };
    // Use only the candidate captured before acquiring owner/run locks. Some
    // production ports replay predecessor evidence in their own transaction;
    // calling that outer-database API while holding these locks can deadlock.
    const preparationId = candidatePreparationId;
    if (preparationId === null) {
      fail(409, 'TASK_PREPARATION_NOT_READY', 'The exact successor preparation changed before activation');
    }
    const preparation = await deps.preparedTaskStart.assertReadyInTransaction(
      tx as TaskPreparationTransaction, target, preparationId, preliminaryMinimumValidUntil,
    );
    validatePreparedPins(preparation, run, record, target, persistedSuccessor.task_id, claim.claim_id);
    if (!deps.preparedTaskStart.hasUsableStartSession(preparation, preliminaryMinimumValidUntil)) {
      fail(409, 'TASK_PREPARATION_SESSION_UNAVAILABLE', 'The original RAM session does not cover the successor task deadline');
    }

    const environmentEvidenceHash = sha256CanonicalTaskJson({
      preparationId: preparation.intent.preparationId, leaseId: preparation.intent.leaseId,
      runId: preparation.intent.runId, taskIndex: preparation.intent.taskIndex,
      claimId: preparation.intent.claimId, releaseIdentity: preparation.intent.releaseIdentity,
      manifestHash: preparation.intent.manifestHash, taskId: preparation.intent.taskId,
      caseId: preparation.intent.caseId, caseHash: preparation.intent.caseHash,
      initialStateSha256: preparation.intent.initialStateSha256,
      executionIdentityHash: preparation.intent.executionIdentityHash,
      environmentManifestSha256: preparation.intent.environmentManifestSha256,
      applicationSourceHash: preparation.intent.applicationSourceHash,
      generationId: preparation.observation.generationId,
      baselineStateSha256: preparation.observation.baselineStateSha256,
      fixtureEvidence: preparation.observation.fixtureEvidence,
      baselineEvidence: preparation.observation.baselineEvidence,
    });
    // Readiness and the coordinator lease proof can await. Take the authoritative activation
    // timestamp only after those waits, so a slow port cannot consume an unbounded prep interval.
    await deps.preparedTaskStart.assertLeaseHeld?.();
    const activationRows = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
    const activationDate = date(activationRows[0]?.now ?? null);
    if (!activationDate || activationDate.getTime() < predecessorFinishedAt.getTime()) {
      fail(409, 'SUCCESSOR_ACTIVATION_CLOCK_INVALID', 'The database activation timestamp precedes the known predecessor receipt');
    }
    const interval = activationDate.getTime() - predecessorFinishedAt.getTime();
    if (interval < 0 || interval > runPolicy.timeoutSeconds * 1000) {
      fail(409, 'SUCCESSOR_PREPARATION_TIMEOUT', 'The persisted successor preparation interval exceeded its immutable bound');
    }
    const newDeadline = new Date(oldDeadline.getTime() + interval);
    const taskDeadline = new Date(Math.min(activationDate.getTime() + taskTimeoutSeconds! * 1000, newDeadline.getTime()));
    if (taskDeadline.getTime() <= activationDate.getTime()) {
      fail(409, 'SUCCESSOR_OVERALL_TIME_EXHAUSTED', 'No execution time remains for the selected successor');
    }
    const minimumValidUntil = taskDeadline.toISOString();
    if (!deps.preparedTaskStart.hasUsableStartSession(preparation, minimumValidUntil)) {
      fail(409, 'TASK_PREPARATION_SESSION_UNAVAILABLE', 'The original RAM session does not cover the successor task deadline');
    }
    const updatedTask = await query<{ task_index: number }>(tx, sql`UPDATE oid_run_task SET status='active',
        started_at=${activationDate.toISOString()},deadline_at=${minimumValidUntil},
        snapshot_json=${JSON.stringify({
          taskId: persistedSuccessor.task_id, taskIndex: predecessorTaskIndex + 1,
          releaseIdentity: run.release_identity, manifestHash: run.manifest_hash,
        })}::jsonb
      WHERE run_id=${run.id} AND task_index=${predecessorTaskIndex + 1} AND task_id=${persistedSuccessor.task_id}
        AND status='queued' AND closure_status='open' AND started_at IS NULL AND finished_at IS NULL
      RETURNING task_index`);
    if (updatedTask.length !== 1) fail(409, 'SUCCESSOR_ACTIVATION_CONFLICT', 'The queued successor changed before activation');
    await tx.execute(sql`UPDATE oid_benchmark_run SET overall_deadline=${newDeadline.toISOString()},
        environment_id=${preparation.intent.environmentId},environment_evidence_hash=${environmentEvidenceHash}
      WHERE id=${run.id} AND status='running'`);

    const inserted = await insertTaskExecutionBindingInTransaction(tx as TaskExecutionBindingReader, {
      runId: preparation.intent.runId, taskIndex: preparation.intent.taskIndex,
      envId: preparation.intent.environmentId, generationId: preparation.observation.generationId!,
      manifestHash: preparation.intent.environmentManifestSha256,
      applicationSourceHash: preparation.intent.applicationSourceHash,
      ...(preparation.observation.participantId ? { participantId: preparation.observation.participantId } : {}),
      ...(preparation.observation.payerAddress ? { payerAddress: preparation.observation.payerAddress } : {}),
    });
    if (!inserted.inserted) {
      fail(409, 'TASK_EXECUTION_BINDING_ALREADY_EXISTS', 'The successor already has an immutable execution binding');
    }
    const binding = inserted.binding;
    const receiptNow = await validatePredecessorReceipt(tx, run, record, predecessorTaskIndex, finalized);
    if (!same(receiptNow, receipt)) {
      fail(409, 'TASK_TERMINALIZATION_MISMATCH', 'The predecessor receipt changed during successor activation');
    }
    const payload = {
      runId: run.id, fromTaskIndex: predecessorTaskIndex, toTaskIndex: predecessorTaskIndex + 1,
      fromTaskId: receipt.taskId, toTaskId: persistedSuccessor.task_id,
      activatedAt: activationDate.toISOString(), predecessorFinishedAt: receipt.finishedAt,
      preparationIntervalMilliseconds: interval, previousOverallDeadline: oldDeadlineIso,
      overallDeadline: newDeadline.toISOString(), taskDeadline: minimumValidUntil,
      successorPreparationPolicyVersion: runPolicy.version,
      successorPreparationTimeoutSeconds: runPolicy.timeoutSeconds,
      predecessorReceipt: {
        closureId: receipt.closureId, inputHash: receipt.inputHash, resultHash: receipt.resultHash,
        outcome: receipt.outcome, preparationId: receipt.preparationId, leaseId: receipt.leaseId,
        generationId: receipt.generationId, fenceEvidenceHash: receipt.fenceEvidenceHash,
      },
      preparation: {
        preparationId: preparation.intent.preparationId, leaseId: preparation.intent.leaseId,
        environmentId: preparation.intent.environmentId, generationId: preparation.observation.generationId,
        environmentManifestSha256: preparation.intent.environmentManifestSha256,
        applicationSourceHash: preparation.intent.applicationSourceHash, environmentEvidenceHash,
      },
      binding,
    };
    const sequenceRows = await query<{ sequence: number }>(tx, sql`
      SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM oid_run_event WHERE run_id=${run.id}`);
    await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      VALUES (${randomUUID()},${run.id},${sequenceRows[0]?.sequence ?? 1},'coordinator','task.activated',
        ${sha256CanonicalTaskJson(payload)},${canonicalTaskJson(payload)}::jsonb)`);
    return {
      runId: run.id, fromTaskIndex: predecessorTaskIndex, toTaskIndex: predecessorTaskIndex + 1,
      fromTaskId: receipt.taskId, toTaskId: persistedSuccessor.task_id,
      activatedAt: activationDate.toISOString(), predecessorFinishedAt: receipt.finishedAt,
      preparationIntervalMilliseconds: interval, previousOverallDeadline: oldDeadlineIso,
      overallDeadline: newDeadline.toISOString(), taskDeadline: minimumValidUntil,
      successorPreparationPolicyVersion: runPolicy.version,
      successorPreparationTimeoutSeconds: runPolicy.timeoutSeconds,
      replayed: false, preparation, binding,
    };
  });
}

export function activatePreparedTrainingSuccessor(
  deps: TaskSuccessorActivationDependencies,
  input: { runId: string; predecessorTaskIndex: number },
): Promise<TrainingSuccessorActivation> {
  return activatePreparedSuccessorForMode(deps, input, 'training');
}

export function activatePreparedRankedSuccessor(
  deps: TaskSuccessorActivationDependencies,
  input: { runId: string; predecessorTaskIndex: number },
): Promise<RankedSuccessorActivation> {
  return activatePreparedSuccessorForMode(deps, input, 'ranked');
}

