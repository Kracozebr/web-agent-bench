/**
 * Private normal completion for a fully known training run.
 *
 * This module does not choose or activate a successor, resolve unknown
 * evidence, refund a run, publish ranked eligibility, or call an executor.
 * It commits a known non-final task terminalization or the final run transition
 * only after immutable task records and original environment fences verify.
 */
import { createHash, randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import type { TaskEvaluationResult, EvaluateTaskInput } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type TaskReleaseQuerySource, type ValidatedTaskReleaseRecord } from './task-release.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import type { TaskId } from './task-catalog.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

export interface TaskRunCompletionDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  /** Re-reads the exact sealed raw evidence packet in this transaction. */
  evidenceSource: TaskEvaluationEvidenceSource;
}

export type CompletedTrainingRun = {
  runId: string;
  status: 'completed';
  finishedAt: string;
  replayed: boolean;
};

export type FinalizedTrainingTask = {
  runId: string;
  taskIndex: number;
  taskId: string;
  status: 'completed' | 'failed';
  finishedAt: string;
  replayed: boolean;
};

type RunRow = {
  id: string; intent_id: string; owner_id: string; agent_id: string; mode: string; task_ids: string[];
  release_identity: string; benchmark_version: string; manifest_hash: string; benchmark_hash: string; policy_hash: string;
  access_generation: number; agent_policy_revision: number; status: string; started_at: Date | string | null;
  overall_deadline: Date | string | null; finished_at: Date | string | null; terminal_reason: string | null;
  cancellation_reason: string | null; cancellation_requested_at: Date | string | null; environment_id: string | null;
};

type TaskRow = {
  run_id: string; task_index: number; task_id: string; status: string; closure_status: string; closure_id: string | null;
  closure_operation_id: string | null; closure_payload_hash: string | null; closure_reason: string | null;
  accepted_action_sequence: string | number; action_cutoff_sequence: string | number | null;
  reconciled_action_sequence: string | number; closed_at: Date | string | null; started_at: Date | string | null;
  finished_at: Date | string | null;
};

type EvaluationRow = {
  run_id: string; task_index: number; closure_id: string; task_id: string; release_identity: string;
  manifest_hash: string; case_hash: string; rubric_hash: string; input_hash: string; result_hash: string;
  evaluator_source_hash: string; observation_evidence: unknown; result_json: unknown; input_json: unknown;
};

type BundleRow = {
  run_id: string; task_index: number; owner_id: string; agent_id: string; closure_id: string;
  closure_operation_id: string | null; closure_payload_hash: string; closure_reason: string; task_id: string;
  release_identity: string; release_manifest_hash: string; case_id: string; case_hash: string; rubric_hash: string;
  environment_id: string; preparation_id: string; lease_id: string; generation_id: string;
  environment_manifest_hash: string; application_source_hash: string; execution_identity_hash: string;
  initial_state_sha256: string; action_cutoff_sequence: string | number; reconciled_action_sequence: string | number;
  observation_cutoff_sequence: string | number; cutoff_evidence: unknown; bundle_hash: string; bundle_json: unknown;
};

type PreparationRow = {
  preparation_id: string; run_id: string; task_index: number; claim_id: string; lease_id: string; environment_id: string;
  release_identity: string; manifest_hash: string; task_id: string; case_id: string; case_hash: string;
  initial_state_sha256: string; execution_identity_hash: string; environment_manifest_sha256: string;
  application_source_hash: string; lease_state: string; fence_evidence: unknown; generation_id: string | null;
  preparation_status: string; baseline_state_sha256: string | null; fixture_evidence: unknown; baseline_evidence: unknown;
  generated_id: string | null; generated_environment_id: string | null;
};

function fail(status: number, code: string, message: string): never {
  throw new HttpError(status, code, message);
}

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('The PostgreSQL driver returned an unexpected run completion result');
  return value as T[];
}

async function query<T>(tx: Transaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

function jsonValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return null; }
}

function object(value: unknown): Record<string, unknown> | null {
  const parsed = jsonValue(value);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
}

function same(left: unknown, right: unknown): boolean {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function date(value: Date | string | null): Date | null {
  if (value === null) return null;
  const result = value instanceof Date ? value : new Date(value);
  return Number.isFinite(result.getTime()) ? result : null;
}

function sequence(value: string | number | null): bigint | null {
  if (value === null) return null;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n ? parsed : null;
  } catch { return null; }
}

function safeHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function knownResult(value: unknown, taskId: string): TaskEvaluationResult | null {
  const result = object(value);
  if (!result || result.taskId !== taskId || result.status !== 'known' ||
      !['passed', 'partial', 'failed'].includes(String(result.outcome)) ||
      !Array.isArray(result.unknownReasons) || result.unknownReasons.length !== 0 ||
      !(result.operatingExpenseUsdcUnits === null || (typeof result.operatingExpenseUsdcUnits === 'string' && /^(0|[1-9][0-9]*)$/.test(result.operatingExpenseUsdcUnits)))) return null;
  const credit = object(result.credit);
  if (!credit || typeof credit.numerator !== 'string' || typeof credit.denominator !== 'string' ||
      !/^(0|[1-9][0-9]*)$/.test(credit.numerator) || !/^[1-9][0-9]*$/.test(credit.denominator)) return null;
  const numerator = BigInt(credit.numerator), denominator = BigInt(credit.denominator);
  if (numerator > denominator ||
      (result.outcome === 'passed' && numerator !== denominator) ||
      (result.outcome === 'failed' && numerator !== 0n) ||
      (result.outcome === 'partial' && (numerator === 0n || numerator === denominator))) return null;
  const violation = result.mandatoryViolation;
  if (!(violation === null || (object(violation) && typeof object(violation)!.rule === 'string' &&
      Array.isArray(object(violation)!.observationIds) && (object(violation)!.observationIds as unknown[]).every((id) => typeof id === 'string')))) return null;
  return result as unknown as TaskEvaluationResult;
}

function terminalTaskStatus(result: TaskEvaluationResult): 'completed' | 'failed' {
  return result.outcome === 'failed' ? 'failed' : 'completed';
}

function expectedTaskOrder(record: ValidatedTaskReleaseRecord, taskIds: string[]): boolean {
  const cases = record.manifest.cases.training;
  const order = cases.map((entry) => entry.taskId).filter((taskId) => taskIds.includes(taskId));
  return order.length === taskIds.length && order.every((taskId, index) => taskId === taskIds[index]);
}

function evidenceManifest(input: EvaluateTaskInput): unknown {
  const references = [input.run.cutoffEvidence, input.observations.captureEvidence];
  for (const value of Object.values(input.observations)) if (Array.isArray(value)) {
    for (const item of value) if (item && typeof item === 'object' && 'evidence' in item) references.push((item as { evidence: typeof input.run.cutoffEvidence }).evidence);
  }
  const unique = new Map(references.map((reference) => [canonicalTaskJson(reference), structuredClone(reference)]));
  return { schemaVersion: 'bts-evaluation-evidence-manifest/v1', references: [...unique.values()] };
}

function assertEvidenceReference(value: unknown): Record<string, unknown> {
  const reference = object(value);
  if (!reference || typeof reference.path !== 'string' || !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(reference.path) ||
      !safeHash(reference.sha256) || reference.boundary !== 'actual_tool_http_x402_local_evm_application_store') {
    fail(409, 'TASK_FENCE_EVIDENCE_MISMATCH', 'The original environment fence evidence is invalid');
  }
  return reference;
}

function checkEvaluationBinding(inputValue: unknown, row: RunRow, task: TaskRow, taskCase: Record<string, unknown>,
  record: ValidatedTaskReleaseRecord, bundle: BundleRow, bundleJson: Record<string, unknown>, result: TaskEvaluationResult): void {
  const input = object(inputValue) as unknown as EvaluateTaskInput | null;
  if (!input || !same(input.taskCase, taskCase) || !same(input.release, record.manifest)) {
    fail(409, 'TASK_EVALUATION_BINDING_MISMATCH', 'The immutable evaluation input differs from the pinned release case');
  }
  const binding = object(bundleJson.binding);
  const closure = object(bundleJson.closure);
  const execution = object(bundleJson.execution);
  const cutoff = object(bundleJson.cutoff);
  const observationBinding = object(input.observations?.binding);
  const taskRun = object(input.run);
  if (!binding || !closure || !execution || !cutoff || !observationBinding || !taskRun ||
      !same(input.observations, bundleJson.observations) ||
      binding.ownerId !== row.owner_id || binding.agentId !== row.agent_id || binding.runId !== row.id ||
      binding.environmentId !== bundle.environment_id || binding.releaseIdentity !== row.release_identity ||
      binding.manifestHash !== row.manifest_hash || binding.caseId !== taskCase.caseId ||
      binding.caseHash !== taskCase.caseHash || binding.rubricHash !== taskCase.rubricHash || binding.taskId !== task.task_id ||
      closure.closureId !== task.closure_id || closure.operationId !== task.closure_operation_id ||
      closure.payloadHash !== task.closure_payload_hash || closure.reason !== task.closure_reason ||
      BigInt(String(closure.actionCutoffSequence)) !== BigInt(String(task.action_cutoff_sequence)) ||
      BigInt(String(closure.reconciledActionSequence)) !== BigInt(String(task.reconciled_action_sequence)) ||
      execution.preparationId !== bundle.preparation_id || execution.leaseId !== bundle.lease_id ||
      execution.generationId !== bundle.generation_id || execution.environmentManifestHash !== bundle.environment_manifest_hash ||
      execution.applicationSourceHash !== bundle.application_source_hash || execution.executionIdentityHash !== bundle.execution_identity_hash ||
      execution.initialStateSha256 !== bundle.initial_state_sha256 || cutoff.status !== 'authoritative' ||
      BigInt(String(cutoff.observationSequence)) !== BigInt(String(bundle.observation_cutoff_sequence)) ||
      !same(cutoff.evidence, bundle.cutoff_evidence) ||
      taskRun.ownerId !== row.owner_id || taskRun.agentId !== row.agent_id || taskRun.runId !== row.id ||
      taskRun.environmentId !== bundle.environment_id || taskRun.releaseIdentity !== row.release_identity ||
      taskRun.manifestHash !== row.manifest_hash || taskRun.caseId !== taskCase.caseId ||
      taskRun.caseHash !== taskCase.caseHash || taskRun.rubricHash !== taskCase.rubricHash || taskRun.taskId !== task.task_id ||
      taskRun.acceptedActionCutoffSequence !== Number(task.action_cutoff_sequence) ||
      taskRun.reconciledThroughActionSequence !== Number(task.reconciled_action_sequence) ||
      taskRun.observationCutoffSequence !== Number(bundle.observation_cutoff_sequence) ||
      taskRun.cutoffStatus !== 'authoritative' || !same(taskRun.cutoffEvidence, cutoff.evidence) ||
      !same(observationBinding, binding) || result.taskId !== task.task_id) {
    fail(409, 'TASK_EVALUATION_BINDING_MISMATCH', 'The immutable evaluation input is not bound to the original task cutoff and generation');
  }
}

async function validateTaskEvidence(tx: Transaction, row: RunRow, task: TaskRow, taskIndex: number,
  record: ValidatedTaskReleaseRecord, evaluation: EvaluationRow, evidenceSource: TaskEvaluationEvidenceSource): Promise<{
    result: TaskEvaluationResult; fenceEvidenceHash: string; preparationId: string; leaseId: string; generationId: string;
  }> {
  const taskCase = record.manifest.cases.training.find((entry) => entry.taskId === task.task_id);
  if (!taskCase || evaluation.run_id !== row.id || evaluation.task_index !== taskIndex || evaluation.closure_id !== task.closure_id ||
      evaluation.task_id !== task.task_id || evaluation.release_identity !== row.release_identity ||
      evaluation.manifest_hash !== row.manifest_hash || evaluation.case_hash !== taskCase.caseHash ||
      evaluation.rubric_hash !== taskCase.rubricHash || !safeHash(evaluation.input_hash) || !safeHash(evaluation.result_hash) ||
      !safeHash(evaluation.evaluator_source_hash) || !task.closure_id) {
    fail(409, 'TASK_EVALUATION_BINDING_MISMATCH', 'The immutable task evaluation does not match its admitted release and closure');
  }
  const input = jsonValue(evaluation.input_json) as unknown as EvaluateTaskInput | null;
  const resultValue = jsonValue(evaluation.result_json);
  if (!input || sha256CanonicalTaskJson(input) !== evaluation.input_hash || sha256CanonicalTaskJson(resultValue) !== evaluation.result_hash) {
    fail(409, 'TASK_EVALUATION_HASH_MISMATCH', 'The retained evaluation input or result hash is invalid');
  }
  const result = knownResult(resultValue, task.task_id);
  if (!result) fail(409, 'TASK_EVALUATION_NOT_KNOWN', 'Every selected task requires a final known immutable evaluation');
  const refreshedInput = await evidenceSource.load({ runId: row.id, taskIndex, closureId: task.closure_id! }, tx);
  if (!refreshedInput || !same(refreshedInput, input)) {
    fail(409, 'TASK_EVALUATION_EVIDENCE_MISMATCH', 'The original hash-backed task evidence cannot be reloaded exactly');
  }

  const bundleRows = await query<BundleRow>(tx, sql`SELECT run_id,task_index,owner_id,agent_id,closure_id,closure_operation_id,
      closure_payload_hash,closure_reason,task_id,release_identity,release_manifest_hash,case_id,case_hash,rubric_hash,
      environment_id,preparation_id,lease_id,generation_id,environment_manifest_hash,application_source_hash,
      execution_identity_hash,initial_state_sha256,action_cutoff_sequence::text AS action_cutoff_sequence,
      reconciled_action_sequence::text AS reconciled_action_sequence,observation_cutoff_sequence::text AS observation_cutoff_sequence,
      cutoff_evidence,bundle_hash,bundle_json
    FROM oid_run_task_observation_bundle WHERE run_id=${row.id} AND task_index=${taskIndex}`);
  const bundle = bundleRows[0];
  const bundleJson = object(bundle?.bundle_json);
  if (!bundle || !bundleJson || bundle.run_id !== row.id || bundle.task_index !== taskIndex ||
      bundle.owner_id !== row.owner_id || bundle.agent_id !== row.agent_id || bundle.closure_id !== task.closure_id ||
      bundle.closure_operation_id !== task.closure_operation_id || bundle.closure_payload_hash !== task.closure_payload_hash ||
      bundle.closure_reason !== task.closure_reason || bundle.task_id !== task.task_id ||
      bundle.release_identity !== row.release_identity || bundle.release_manifest_hash !== row.manifest_hash ||
      bundle.case_id !== taskCase.caseId || bundle.case_hash !== taskCase.caseHash || bundle.rubric_hash !== taskCase.rubricHash ||
      bundle.action_cutoff_sequence === null || BigInt(bundle.action_cutoff_sequence) !== BigInt(String(task.action_cutoff_sequence)) ||
      BigInt(bundle.reconciled_action_sequence) !== BigInt(String(task.reconciled_action_sequence)) ||
      bundle.bundle_hash !== sha256CanonicalTaskJson(bundleJson)) {
    fail(409, 'TASK_OBSERVATION_BUNDLE_MISMATCH', 'The retained observation bundle does not match the exact task cutoff');
  }

  const prepRows = await query<PreparationRow>(tx, sql`SELECT i.preparation_id,i.run_id,i.task_index,i.claim_id,i.lease_id,i.environment_id,
      i.release_identity,i.manifest_hash,i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
      i.environment_manifest_sha256,i.application_source_hash,l.state AS lease_state,l.fence_evidence,
      o.generation_id,o.status AS preparation_status,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence,
      g.generation_id AS generated_id,g.environment_id AS generated_environment_id
    FROM oid_task_preparation_intent i
    JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT generation_id,status,baseline_state_sha256,fixture_evidence,baseline_evidence
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    LEFT JOIN oid_task_preparation_generation g ON g.preparation_id=i.preparation_id
    WHERE i.run_id=${row.id} AND i.task_index=${taskIndex} FOR UPDATE OF i,l`);
  const prep = prepRows[0];
  const execution = object(bundleJson.execution);
  const fence = object(prep?.fence_evidence);
  const executionIdentity = record.manifest.executionIdentity;
  if (!prep || !execution || !fence || prep.lease_state !== 'fenced' || prep.preparation_status !== 'fenced' ||
      !prep.generation_id || prep.generated_id !== prep.generation_id || prep.generated_environment_id !== prep.environment_id ||
      prep.run_id !== row.id || prep.task_index !== taskIndex || prep.preparation_id !== execution.preparationId ||
      prep.lease_id !== execution.leaseId || prep.environment_id !== bundle.environment_id ||
      prep.release_identity !== row.release_identity || prep.manifest_hash !== row.manifest_hash || prep.task_id !== task.task_id ||
      prep.case_id !== taskCase.caseId || prep.case_hash !== taskCase.caseHash ||
      prep.initial_state_sha256 !== taskCase.initialState.stateSha256 || prep.baseline_state_sha256 !== prep.initial_state_sha256 ||
      prep.execution_identity_hash !== taskCase.executionIdentityHash ||
      prep.environment_manifest_sha256 !== executionIdentity.environmentManifestSha256 ||
      prep.application_source_hash !== executionIdentity.x402ServiceSha256 ||
      prep.generation_id !== bundle.generation_id || prep.environment_manifest_sha256 !== bundle.environment_manifest_hash ||
      prep.application_source_hash !== bundle.application_source_hash || prep.execution_identity_hash !== bundle.execution_identity_hash ||
      fence.confirmed !== true || fence.preparationId !== prep.preparation_id || fence.leaseId !== prep.lease_id ||
      fence.environmentId !== prep.environment_id || fence.generationId !== prep.generation_id) {
    fail(409, 'TASK_ORIGINAL_GENERATION_NOT_FENCED', 'The original task generation is not exactly fenced');
  }
  const fenceEvidence = assertEvidenceReference(fence.evidence);
  assertEvidenceReference(prep.fixture_evidence);
  assertEvidenceReference(prep.baseline_evidence);

  const bindingRows = await query<{ env_id: string; generation_id: string; manifest_hash: string; application_source_hash: string }>(tx,
    sql`SELECT env_id,generation_id,manifest_hash,application_source_hash FROM oid_task_execution_binding
      WHERE run_id=${row.id} AND task_index=${taskIndex} FOR KEY SHARE`);
  const binding = bindingRows[0];
  if (!binding || binding.env_id !== prep.environment_id || binding.generation_id !== prep.generation_id ||
      binding.manifest_hash !== prep.environment_manifest_sha256 || binding.application_source_hash !== prep.application_source_hash) {
    fail(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The fenced task generation differs from its original execution binding');
  }
  checkEvaluationBinding(input, row, task, taskCase as unknown as Record<string, unknown>, record, bundle, bundleJson, result);
  const storedEvidenceManifest = jsonValue(evaluation.observation_evidence);
  if (!same(storedEvidenceManifest, evidenceManifest(input))) {
    fail(409, 'TASK_EVALUATION_EVIDENCE_MISMATCH', 'The evaluation evidence references differ from its immutable input');
  }
  return { result, fenceEvidenceHash: String(fenceEvidence.sha256), preparationId: prep.preparation_id,
    leaseId: prep.lease_id, generationId: prep.generation_id };
}

async function validateActionCutoff(tx: Transaction, row: RunRow, task: TaskRow, taskIndex: number): Promise<void> {
  const cutoff = sequence(task.action_cutoff_sequence);
  const accepted = sequence(task.accepted_action_sequence);
  const reconciled = sequence(task.reconciled_action_sequence);
  const taskClosedAt = date(task.closed_at);
  if (task.closure_status !== 'closed' || !task.closure_id || !task.closure_payload_hash || !task.closure_reason ||
      cutoff === null || accepted !== cutoff || reconciled === null || reconciled < cutoff || !taskClosedAt ||
      !task.started_at || !['agent_finish', 'task_deadline', 'run_deadline'].includes(task.closure_reason)) {
    fail(409, 'TASK_CUTOFF_NOT_FINAL', 'Every selected task needs one closed and reconciled action cutoff');
  }
  const closureRows = await query<{ id: string; operation_id: string | null; payload_hash: string; reason: string;
    action_cutoff_sequence: string | number; owner_id: string; agent_id: string; actor_kind: string }>(tx, sql`SELECT id,operation_id,
      payload_hash,reason,action_cutoff_sequence::text AS action_cutoff_sequence,owner_id,agent_id,actor_kind
    FROM oid_run_task_closure WHERE id=${task.closure_id} AND run_id=${row.id} AND task_index=${taskIndex} FOR KEY SHARE`);
  const closure = closureRows[0];
  if (!closure || closure.owner_id !== row.owner_id || closure.agent_id !== row.agent_id || closure.actor_kind !== 'agent' && closure.actor_kind !== 'coordinator' ||
      closure.operation_id !== task.closure_operation_id || closure.payload_hash !== task.closure_payload_hash ||
      closure.reason !== task.closure_reason || BigInt(closure.action_cutoff_sequence) !== cutoff) {
    fail(409, 'TASK_CLOSURE_MISMATCH', 'The immutable closure journal differs from its task cutoff');
  }
  const receipts = await query<{ action_sequence: string; receipt_status: string | null; outbox_status: string | null }>(tx, sql`SELECT
      a.action_sequence::text AS action_sequence,r.receipt_status,o.status AS outbox_status
    FROM oid_run_task_action a
    LEFT JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    LEFT JOIN oid_run_task_action_outbox o ON o.action_id=a.id
    WHERE a.run_id=${row.id} AND a.task_index=${taskIndex}
    ORDER BY a.action_sequence FOR UPDATE OF a`);
  if (BigInt(receipts.length) !== cutoff || receipts.some((receipt, index) =>
      BigInt(receipt.action_sequence) !== BigInt(index + 1) ||
      !['observed', 'rejected_before_execution'].includes(String(receipt.receipt_status)) || receipt.outbox_status !== 'delivered')) {
    fail(409, 'TASK_ACTIONS_NOT_RECONCILED', 'Every admitted action through the cutoff must have a resolved receipt');
  }
}

async function validateTaskEvaluatedEvent(tx: Transaction, row: RunRow, task: TaskRow, taskIndex: number, evaluation: EvaluationRow): Promise<void> {
  const events = await query<{ payload_hash: string; payload_json: unknown }>(tx, sql`SELECT payload_hash,payload_json FROM oid_run_event
    WHERE run_id=${row.id} AND event_type='task.evaluated' ORDER BY sequence`);
  const matches = events.filter((event) => {
    const payload = object(event.payload_json);
    return payload?.taskIndex === taskIndex;
  });
  const expected = { taskIndex, taskId: task.task_id, closureId: task.closure_id, releaseIdentity: row.release_identity,
    manifestHash: row.manifest_hash, inputHash: evaluation.input_hash, resultHash: evaluation.result_hash,
    evaluatorSourceHash: evaluation.evaluator_source_hash };
  if (matches.length !== 1 || matches[0]!.payload_hash !== sha256CanonicalTaskJson(expected) || !same(matches[0]!.payload_json, expected)) {
    fail(409, 'TASK_EVALUATION_EVENT_MISMATCH', 'The immutable evaluation event is missing or inconsistent');
  }
}

function completionPayload(run: RunRow, taskIds: string[], finishedAt: string,
  verified: Array<{ taskIndex: number; taskId: string; closureId: string; inputHash: string; resultHash: string;
    preparationId: string; leaseId: string; generationId: string; fenceEvidenceHash: string }>) {
  return { runId: run.id, mode: run.mode, taskIds, finishedAt, tasks: verified };
}

async function validateTaskSet(tx: Transaction, row: RunRow, record: ValidatedTaskReleaseRecord, replayed: boolean) {
  if (!Array.isArray(row.task_ids) || row.task_ids.length === 0 || row.task_ids.length > 12 ||
      row.task_ids.some((taskId) => typeof taskId !== 'string') || new Set(row.task_ids).size !== row.task_ids.length ||
      !expectedTaskOrder(record, row.task_ids)) {
    fail(409, 'RUN_TASK_SELECTION_MISMATCH', 'The selected training tasks do not match the immutable release order');
  }
  const tasks = await query<TaskRow & { result_json: unknown }>(tx, sql`SELECT run_id,task_index,task_id,status,closure_status,closure_id,
      closure_operation_id,closure_payload_hash,closure_reason,accepted_action_sequence::text AS accepted_action_sequence,
      action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
      closed_at,started_at,finished_at,result_json
    FROM oid_run_task WHERE run_id=${row.id} ORDER BY task_index FOR UPDATE`);
  if (tasks.length !== row.task_ids.length || tasks.some((task, index) => task.task_index !== index || task.task_id !== row.task_ids[index])) {
    fail(409, 'RUN_TASK_SET_INCOMPLETE', 'The run task rows do not exactly match the selected task set');
  }
  const claimRows = await query<{ claim_id: string; owner_id: string; agent_id: string; status: string; released_at: Date | string | null }>(tx,
    sql`SELECT claim_id,owner_id,agent_id,status,released_at FROM oid_run_dispatch_claim WHERE run_id=${row.id} FOR UPDATE`);
  const slotRows = await query<{ run_id: string; owner_id: string; agent_id: string; claim_id: string; state: string; released_at: Date | string | null }>(tx,
    sql`SELECT run_id,owner_id,agent_id,claim_id,state,released_at FROM oid_run_execution_slot WHERE run_id=${row.id} FOR UPDATE`);
  const claim = claimRows[0];
  const slot = slotRows[0];
  if (!claim || claim.owner_id !== row.owner_id || claim.agent_id !== row.agent_id || !claim.claim_id ||
      (!replayed && (claim.status !== 'claimed' || claim.released_at !== null || !slot || slot.run_id !== row.id ||
        slot.owner_id !== row.owner_id || slot.agent_id !== row.agent_id || slot.claim_id !== claim.claim_id ||
        slot.state !== 'running' || slot.released_at !== null)) ||
      (replayed && (claim.status !== 'released' || !claim.released_at || slot !== undefined))) {
    fail(409, 'RUN_CLAIM_OR_SLOT_MISMATCH', 'The run claim and execution slot are not in the expected terminal state');
  }
  return { tasks, claim, slot };
}

async function assertNoCancellationHistory(tx: Transaction, row: RunRow, completedAt?: Date): Promise<void> {
  if (row.cancellation_reason !== null || row.cancellation_requested_at !== null) {
    fail(409, 'RUN_CANCELLATION_HISTORY', 'A cancellation-requested run cannot complete normally');
  }
  const before = completedAt ? sql`AND created_at<=${completedAt.toISOString()}::timestamptz` : sql``;
  const history = await query<{ revoked: boolean; mode_removed: boolean; receipt: boolean; pending_cancel: boolean }>(tx, sql`SELECT
      EXISTS(SELECT 1 FROM oid_agent_cancellation_outbox WHERE owner_id=${row.owner_id} AND agent_id=${row.agent_id}
        AND access_generation>${row.access_generation} ${before}) AS revoked,
      EXISTS(SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${row.owner_id} AND agent_id=${row.agent_id}
        AND mode=${row.mode} AND policy_revision>${row.agent_policy_revision} ${before}) AS mode_removed,
      EXISTS(SELECT 1 FROM oid_run_cancellation_receipt c WHERE (${row.id}=ANY(c.cancelled_run_ids) OR ${row.id}=ANY(c.pending_run_ids))
        ${completedAt ? sql`AND c.created_at<=${completedAt.toISOString()}::timestamptz` : sql``}) AS receipt,
      EXISTS(SELECT 1 FROM oid_run_outbox WHERE run_id=${row.id} AND event_type='run.cancel.requested' ${before}) AS pending_cancel`);
  const current = history[0];
  if (current?.revoked || current?.mode_removed || current?.receipt || current?.pending_cancel) {
    fail(409, 'RUN_CANCELLATION_HISTORY', 'A run with access-revocation or cancellation history cannot complete normally');
  }
}

function eventHash(payload: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(payload)).digest('hex');
}

async function completedEvent(tx: Transaction, row: RunRow): Promise<{ payload_hash: string; payload_json: unknown }[]> {
  return query(tx, sql`SELECT payload_hash,payload_json FROM oid_run_event WHERE run_id=${row.id} AND event_type='run.completed'`);
}

function taskTerminalizationPayload(row: RunRow, task: TaskRow, taskIndex: number, evaluation: EvaluationRow,
  result: TaskEvaluationResult, evidence: { preparationId: string; leaseId: string; generationId: string; fenceEvidenceHash: string },
  finishedAt: string) {
  return {
    runId: row.id, taskIndex, taskId: task.task_id, closureId: task.closure_id,
    releaseIdentity: row.release_identity, manifestHash: row.manifest_hash,
    inputHash: evaluation.input_hash, resultHash: evaluation.result_hash,
    outcome: result.outcome, status: terminalTaskStatus(result), finishedAt,
    preparationId: evidence.preparationId, leaseId: evidence.leaseId,
    generationId: evidence.generationId, fenceEvidenceHash: evidence.fenceEvidenceHash,
  };
}

async function taskTerminalizationEvents(tx: Transaction, row: RunRow, taskIndex: number) {
  const events = await query<{ source: string; payload_hash: string; payload_json: unknown }>(tx, sql`SELECT source,payload_hash,payload_json
    FROM oid_run_event WHERE run_id=${row.id} AND event_type='task.terminalized' ORDER BY sequence`);
  return events.filter((event) => object(event.payload_json)?.taskIndex === taskIndex);
}

async function validateTaskTerminalizationEvent(tx: Transaction, row: RunRow, task: TaskRow, taskIndex: number,
  evaluation: EvaluationRow, result: TaskEvaluationResult,
  evidence: { preparationId: string; leaseId: string; generationId: string; fenceEvidenceHash: string }): Promise<void> {
  const finishedAt = date(task.finished_at);
  if (!finishedAt) fail(409, 'TASK_TERMINALIZATION_MISMATCH', 'A terminal task requires its immutable finish time');
  const expected = taskTerminalizationPayload(row, task, taskIndex, evaluation, result, evidence, finishedAt.toISOString());
  const matches = await taskTerminalizationEvents(tx, row, taskIndex);
  if (matches.length !== 1 || matches[0]!.source !== 'coordinator' ||
      matches[0]!.payload_hash !== eventHash(expected) || !same(matches[0]!.payload_json, expected)) {
    fail(409, 'TASK_TERMINALIZATION_EVENT_MISMATCH', 'The task terminalization event is missing or inconsistent');
  }
}

async function taskEvaluation(tx: Transaction, runId: string, taskIndex: number): Promise<EvaluationRow | null> {
  const found = await query<EvaluationRow>(tx, sql`SELECT run_id,task_index,closure_id,task_id,release_identity,manifest_hash,
      case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json
    FROM oid_run_task_evaluation WHERE run_id=${runId} AND task_index=${taskIndex} FOR UPDATE`);
  return found[0] ?? null;
}

/**
 * Atomically terminalize one known, non-final training task after its original
 * generation has been fenced. The run charge, overall clock, claim and slot
 * remain owned by the run; this function does not prepare or activate a successor.
 */
export async function finalizeKnownTrainingTask(
  deps: TaskRunCompletionDependencies,
  input: { runId: string; taskIndex: number },
): Promise<FinalizedTrainingTask> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.runId) ||
      !Number.isSafeInteger(input.taskIndex) || input.taskIndex < 0 || input.taskIndex > 11) {
    fail(400, 'INVALID_TASK_TERMINALIZATION_TARGET', 'A run UUID and bounded task index are required');
  }
  const runId = input.runId.toLowerCase();
  const taskIndex = input.taskIndex;
  return deps.db.transaction(async (tx) => {
    const candidates = await query<{ owner_id: string; agent_id: string }>(tx,
      sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${runId}`);
    const candidate = candidates[0];
    if (!candidate) fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
    const owners = await query<{ admission_status: string }>(tx, sql`SELECT admission_status FROM oid_owner
      WHERE id=${candidate.owner_id} FOR NO KEY UPDATE`);
    const agents = await query<{ id: string; owner_id: string; access_generation: number; access_revoked_at: Date | string | null }>(tx,
      sql`SELECT id,owner_id,access_generation,access_revoked_at FROM oid_agent
        WHERE id=${candidate.agent_id} AND owner_id=${candidate.owner_id} FOR NO KEY UPDATE`);
    const policyRows = await query<{ training: boolean }>(tx, sql`SELECT training FROM oid_agent_policy
      WHERE agent_id=${candidate.agent_id} FOR UPDATE`);
    const runRows = await query<RunRow>(tx, sql`SELECT id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,access_generation,agent_policy_revision,status,started_at,overall_deadline,
        finished_at,terminal_reason,cancellation_reason,cancellation_requested_at,environment_id
      FROM oid_benchmark_run WHERE id=${runId} AND owner_id=${candidate.owner_id} AND agent_id=${candidate.agent_id} FOR UPDATE`);
    const row = runRows[0];
    const agent = agents[0];
    const policy = policyRows[0];
    if (!row || !agent || !policy || row.owner_id !== candidate.owner_id || row.agent_id !== candidate.agent_id) {
      fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
    }
    if (row.mode !== 'training') fail(409, 'TRAINING_TASK_REQUIRED', 'Only selected training tasks use this terminalization path');
    if (!date(row.started_at) || !date(row.overall_deadline) || row.terminal_reason !== null ||
        (row.status !== 'running' && row.status !== 'completed')) {
      fail(409, 'RUN_NOT_TERMINALIZABLE', 'Only a started, non-cancelled training run can terminalize a selected task');
    }
    const completedRunReplay = row.status === 'completed';
    const completedAt = completedRunReplay ? date(row.finished_at) : null;
    if (completedRunReplay && !completedAt) fail(409, 'RUN_NOT_TERMINALIZABLE', 'A completed run requires its immutable finish time');
    if (!completedRunReplay && (owners[0]?.admission_status !== 'admitted' || agent.access_revoked_at !== null ||
        agent.access_generation !== row.access_generation || !policy.training)) {
      fail(409, 'RUN_ACCESS_NOT_CURRENT', 'Current owner and agent access is required to terminalize a task');
    }

    const record = await deps.taskReleaseSource.getValidatedReleaseRecord(row.release_identity, row.manifest_hash, tx);
    if (!record || record.releaseIdentity !== row.release_identity || record.manifestHash !== row.manifest_hash ||
        record.benchmarkVersion !== row.benchmark_version || record.benchmarkHash !== row.benchmark_hash || record.policyHash !== row.policy_hash ||
        record.manifest.releaseIdentity !== row.release_identity || record.manifest.manifestHash !== row.manifest_hash) {
      fail(503, 'PINNED_RELEASE_UNAVAILABLE', 'The immutable admitted task release cannot be verified');
    }
    const { tasks } = await validateTaskSet(tx, row, record, completedRunReplay);
    if (taskIndex >= tasks.length - 1) fail(409, 'FINAL_TASK_REQUIRES_RUN_COMPLETION', 'The final selected task must use normal run completion');
    const current = tasks[taskIndex]!;
    if (!current || row.task_ids[taskIndex] !== current.task_id) fail(404, 'TASK_NOT_FOUND', 'The selected task does not exist in this run');

    const alreadyTerminal = current.status === 'completed' || current.status === 'failed';
    const desiredFinishedAt = date(current.finished_at);
    if ((!completedRunReplay && row.status !== 'running') || (completedRunReplay && !alreadyTerminal) ||
        (alreadyTerminal !== Boolean(desiredFinishedAt)) ||
        (!alreadyTerminal && current.status !== 'active')) {
      fail(409, 'TASK_TERMINALIZATION_CONFLICT', 'The selected task is neither active nor an exact terminalization replay');
    }
    if (alreadyTerminal && !desiredFinishedAt) fail(409, 'TASK_TERMINALIZATION_CONFLICT', 'A terminal task requires its immutable finish time');

    await assertNoCancellationHistory(tx, row, completedAt ?? undefined);
    for (let index = 0; index < taskIndex; index += 1) {
      const prior = tasks[index]!;
      if (prior.status !== 'completed' && prior.status !== 'failed' || !date(prior.finished_at)) {
        fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'Every preceding selected task must have a known terminal outcome');
      }
      await validateActionCutoff(tx, row, prior, index);
      const priorEvaluation = await taskEvaluation(tx, row.id, index);
      if (!priorEvaluation) fail(409, 'RUN_EVALUATIONS_INCOMPLETE', 'Every preceding selected task requires an immutable evaluation');
      const priorEvidence = await validateTaskEvidence(tx, row, prior, index, record, priorEvaluation, deps.evidenceSource);
      if (prior.status !== terminalTaskStatus(priorEvidence.result)) {
        fail(409, 'RUN_TASK_TERMINAL_STATE_MISMATCH', 'A preceding task status differs from its known evaluation');
      }
      await validateTaskEvaluatedEvent(tx, row, prior, index, priorEvaluation);
      await validateTaskTerminalizationEvent(tx, row, prior, index, priorEvaluation, priorEvidence.result, priorEvidence);
    }

    await validateActionCutoff(tx, row, current, taskIndex);
    const evaluation = await taskEvaluation(tx, row.id, taskIndex);
    if (!evaluation) fail(409, 'TASK_EVALUATION_NOT_FOUND', 'The selected task requires an immutable evaluation');
    const verified = await validateTaskEvidence(tx, row, current, taskIndex, record, evaluation, deps.evidenceSource);
    await validateTaskEvaluatedEvent(tx, row, current, taskIndex, evaluation);
    const terminalStatus = terminalTaskStatus(verified.result);
    if (alreadyTerminal) {
      if (current.status !== terminalStatus) fail(409, 'TASK_TERMINAL_STATE_MISMATCH', 'The stored task status differs from its known evaluation');
      await validateTaskTerminalizationEvent(tx, row, current, taskIndex, evaluation, verified.result, verified);
      return { runId: row.id, taskIndex, taskId: current.task_id, status: terminalStatus,
        finishedAt: desiredFinishedAt!.toISOString(), replayed: true };
    }

    if ((await taskTerminalizationEvents(tx, row, taskIndex)).length !== 0) {
      fail(409, 'TASK_TERMINALIZATION_EVENT_MISMATCH', 'An active task already has terminalization history');
    }

    if (tasks.some((task, index) => index !== taskIndex && task.status === 'active') ||
        tasks.slice(taskIndex + 1).some((task) => task.status !== 'queued' || task.started_at !== null || task.finished_at !== null)) {
      fail(409, 'RUN_TASK_ORDER_CONFLICT', 'Only the current active task may be terminalized before its queued successors');
    }
    const nowRows = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
    const now = date(nowRows[0]?.now ?? null);
    if (!now) throw new Error('PostgreSQL did not return a task terminalization timestamp');
    const finishedAt = now.toISOString();
    const updated = await query<{ task_index: number }>(tx, sql`UPDATE oid_run_task SET status=${terminalStatus},finished_at=${finishedAt}
      WHERE run_id=${row.id} AND task_index=${taskIndex} AND task_id=${current.task_id} AND status='active' AND finished_at IS NULL
      RETURNING task_index`);
    if (updated.length !== 1) fail(409, 'TASK_TERMINALIZATION_CONFLICT', 'The selected task changed before terminalization');
    const terminalizedTask = { ...current, status: terminalStatus, finished_at: finishedAt };
    const payload = taskTerminalizationPayload(row, terminalizedTask, taskIndex, evaluation, verified.result, verified, finishedAt);
    const eventRows = await query<{ sequence: number }>(tx, sql`SELECT COALESCE(MAX(sequence),0)+1 AS sequence
      FROM oid_run_event WHERE run_id=${row.id}`);
    await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      VALUES (${randomUUID()},${row.id},${eventRows[0]?.sequence ?? 1},'coordinator','task.terminalized',${eventHash(payload)},
        ${canonicalTaskJson(payload)}::jsonb)`);
    return { runId: row.id, taskIndex, taskId: current.task_id, status: terminalStatus, finishedAt, replayed: false };
  });
}

/**
 * Atomically terminalize a fully known, fully fenced training run.
 * Evaluation and evidence inputs remain the immutable originals; the current
 * wall clock is used only to timestamp completion after the persisted cutoffs
 * have been resolved. No overall-deadline comparison is made here.
 */
export async function completeKnownTrainingRun(
  deps: TaskRunCompletionDependencies,
  input: { runId: string },
): Promise<CompletedTrainingRun> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.runId)) {
    fail(400, 'INVALID_RUN_ID', 'A run UUID is required');
  }
  const runId = input.runId.toLowerCase();
  return deps.db.transaction(async (tx) => {
    const candidates = await query<{ owner_id: string; agent_id: string }>(tx, sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${runId}`);
    const candidate = candidates[0];
    if (!candidate) fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
    const owners = await query<{ admission_status: string }>(tx, sql`SELECT admission_status FROM oid_owner
      WHERE id=${candidate.owner_id} FOR NO KEY UPDATE`);
    const agents = await query<{ id: string; owner_id: string; access_generation: number; access_revoked_at: Date | string | null }>(tx,
      sql`SELECT id,owner_id,access_generation,access_revoked_at FROM oid_agent
        WHERE id=${candidate.agent_id} AND owner_id=${candidate.owner_id} FOR NO KEY UPDATE`);
    const policyRows = await query<{ training: boolean; ranked: boolean }>(tx, sql`SELECT training,ranked FROM oid_agent_policy
      WHERE agent_id=${candidate.agent_id} FOR UPDATE`);
    const runRows = await query<RunRow>(tx, sql`SELECT id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,access_generation,agent_policy_revision,status,started_at,overall_deadline,
        finished_at,terminal_reason,cancellation_reason,cancellation_requested_at,environment_id
      FROM oid_benchmark_run WHERE id=${runId} AND owner_id=${candidate.owner_id} AND agent_id=${candidate.agent_id} FOR UPDATE`);
    const row = runRows[0];
    const agent = agents[0];
    const policy = policyRows[0];
    if (!row || !agent || !policy || row.owner_id !== candidate.owner_id || row.agent_id !== candidate.agent_id) {
      fail(404, 'RUN_NOT_FOUND', 'The run does not exist');
    }
    if (row.mode !== 'training') fail(409, 'RANKED_COMPLETION_REQUIRES_HANDOFF', 'Ranked completion must include its atomic eligibility handoff');
    if (!date(row.started_at) || !date(row.overall_deadline) || row.terminal_reason !== null ||
        (row.status !== 'running' && row.status !== 'completed')) {
      fail(409, 'RUN_NOT_COMPLETABLE', 'Only a normally running or identically completed run can use this completion path');
    }
    const replayed = row.status === 'completed';
    const completedAt = replayed ? date(row.finished_at) : null;
    if (replayed && !completedAt) fail(409, 'RUN_NOT_COMPLETABLE', 'A completed run requires its immutable completion timestamp');
    if (!replayed && (owners[0]?.admission_status !== 'admitted' || agent.access_revoked_at !== null ||
        agent.access_generation !== row.access_generation || !policy.training)) {
      fail(409, 'RUN_ACCESS_NOT_CURRENT', 'Current owner and agent access is required for normal completion');
    }
    await assertNoCancellationHistory(tx, row, completedAt ?? undefined);
    const record = await deps.taskReleaseSource.getValidatedReleaseRecord(row.release_identity, row.manifest_hash, tx);
    if (!record || record.releaseIdentity !== row.release_identity || record.manifestHash !== row.manifest_hash ||
        record.benchmarkVersion !== row.benchmark_version || record.benchmarkHash !== row.benchmark_hash || record.policyHash !== row.policy_hash ||
        record.manifest.releaseIdentity !== row.release_identity || record.manifest.manifestHash !== row.manifest_hash) {
      fail(503, 'PINNED_RELEASE_UNAVAILABLE', 'The immutable admitted task release cannot be verified');
    }
    const { tasks } = await validateTaskSet(tx, row, record, replayed);
    for (let index = 0; index < tasks.length; index += 1) await validateActionCutoff(tx, row, tasks[index]!, index);
    const evaluationRows = await query<EvaluationRow>(tx, sql`SELECT run_id,task_index,closure_id,task_id,release_identity,manifest_hash,
        case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json
      FROM oid_run_task_evaluation WHERE run_id=${row.id} ORDER BY task_index FOR UPDATE`);
    if (evaluationRows.length !== tasks.length || evaluationRows.some((evaluation, index) => evaluation.task_index !== index)) {
      fail(409, 'RUN_EVALUATIONS_INCOMPLETE', 'Every selected task requires one immutable evaluation');
    }
    const verified: Array<{ taskIndex: number; taskId: string; closureId: string; inputHash: string; resultHash: string;
      preparationId: string; leaseId: string; generationId: string; fenceEvidenceHash: string }> = [];
    const desiredStatuses: Array<'completed' | 'failed'> = [];
    for (let index = 0; index < tasks.length; index += 1) {
      const task = tasks[index]!;
      const evaluation = evaluationRows[index]!;
      const evidence = await validateTaskEvidence(tx, row, task, index, record, evaluation, deps.evidenceSource);
      await validateTaskEvaluatedEvent(tx, row, task, index, evaluation);
      const desired = terminalTaskStatus(evidence.result);
      if (replayed) {
        if (task.status !== desired || !date(task.finished_at)) fail(409, 'RUN_TASK_TERMINAL_STATE_MISMATCH', 'A completed run has inconsistent task outcomes');
      } else if (index < tasks.length - 1) {
        if (task.status !== desired || !date(task.finished_at)) fail(409, 'RUN_TASK_PREDECESSOR_NOT_TERMINAL', 'Every preceding selected task must already be terminal');
      } else if (task.status !== 'active' || task.finished_at !== null) {
        fail(409, 'RUN_FINAL_TASK_NOT_ACTIVE', 'Only the final active task may be terminalized by this service');
      }
      desiredStatuses.push(desired);
      verified.push({ taskIndex: index, taskId: task.task_id, closureId: task.closure_id!, inputHash: evaluation.input_hash,
        resultHash: evaluation.result_hash, preparationId: evidence.preparationId, leaseId: evidence.leaseId,
        generationId: evidence.generationId, fenceEvidenceHash: evidence.fenceEvidenceHash });
    }
    const priorCompletionEvents = await completedEvent(tx, row);
    if (replayed) {
      const finishedAt = date(row.finished_at);
      if (!finishedAt || priorCompletionEvents.length !== 1) fail(409, 'RUN_COMPLETION_EVENT_MISMATCH', 'The completed run lacks one authoritative completion event');
      const expected = completionPayload(row, row.task_ids, finishedAt.toISOString(), verified);
      if (priorCompletionEvents[0]!.payload_hash !== eventHash(expected) || !same(priorCompletionEvents[0]!.payload_json, expected)) {
        fail(409, 'RUN_COMPLETION_EVENT_MISMATCH', 'The stored run completion event differs from verified task evidence');
      }
      return { runId: row.id, status: 'completed', finishedAt: finishedAt.toISOString(), replayed: true };
    }
    if (priorCompletionEvents.length !== 0 || row.finished_at !== null) {
      fail(409, 'RUN_COMPLETION_CONFLICT', 'A running run already has terminal completion data');
    }
    const nowRows = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
    const now = date(nowRows[0]?.now ?? null);
    if (!now) throw new Error('PostgreSQL did not return a completion timestamp');
    const finishedAt = now.toISOString();
    const payload = completionPayload(row, row.task_ids, finishedAt, verified);
    for (let index = 0; index < tasks.length; index += 1) {
      const task = tasks[index]!;
      if (task.status === desiredStatuses[index]) continue;
      const updated = await query<{ task_index: number }>(tx, sql`UPDATE oid_run_task SET status=${desiredStatuses[index]},finished_at=${finishedAt}
        WHERE run_id=${row.id} AND task_index=${index} AND status='active' AND finished_at IS NULL RETURNING task_index`);
      if (updated.length !== 1) fail(409, 'RUN_TASK_TERMINAL_CONFLICT', 'The final task changed before run completion');
    }
    const updatedRun = await query<{ id: string }>(tx, sql`UPDATE oid_benchmark_run SET status='completed',finished_at=${finishedAt}
      WHERE id=${row.id} AND status='running' AND finished_at IS NULL AND cancellation_reason IS NULL
        AND cancellation_requested_at IS NULL RETURNING id`);
    if (updatedRun.length !== 1) fail(409, 'RUN_COMPLETION_CONFLICT', 'The run changed before normal completion');
    const nextSequence = await query<{ sequence: number }>(tx, sql`SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM oid_run_event WHERE run_id=${row.id}`);
    await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json,created_at)
      VALUES (${randomUUID()},${row.id},${nextSequence[0]?.sequence ?? 1},'coordinator','run.completed',${eventHash(payload)},
        ${canonicalTaskJson(payload)}::jsonb,${finishedAt})`);
    const released = await query<{ run_id: string }>(tx, sql`UPDATE oid_run_dispatch_claim SET status='released',released_at=${finishedAt}
      WHERE run_id=${row.id} AND status='claimed' RETURNING run_id`);
    if (released.length !== 1) fail(409, 'RUN_CLAIM_RELEASE_CONFLICT', 'The run dispatch claim is no longer active');
    const removed = await query<{ run_id: string }>(tx, sql`DELETE FROM oid_run_execution_slot
      WHERE run_id=${row.id} AND agent_id=${row.agent_id} RETURNING run_id`);
    if (removed.length !== 1) fail(409, 'RUN_SLOT_RELEASE_CONFLICT', 'The run execution slot is no longer owned by this run');
    return { runId: row.id, status: 'completed', finishedAt, replayed: false };
  });
}

