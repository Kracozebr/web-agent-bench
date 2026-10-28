import { collectBefCompositeObservationCandidate } from './bef-composite-observation-collector.js';
import { TASK_IDS } from './task-catalog.js';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { collectBefS1TaskObservationCandidate } from './bef-s1-observation-collector.js';
import { collectBefS2TaskObservationCandidate } from './bef-s2-observation-collector.js';
import { collectBefS4TaskObservationCandidate } from './bef-s4-observation-collector.js';
import { collectBefM1TaskObservationCandidate } from './bef-m1-observation-collector.js';
import { collectBefPaidDataObservationCandidate } from './bef-paid-data-observation-collector.js';
import { collectBefChainTaskObservationCandidate } from './bef-chain-observation-collector.js';
import { collectBefS3TaskObservationCandidate } from './bef-s3-observation-collector.js';
import type { BefFenceProof, BefObservationPorts } from './bef-observation-ports.js';
import { taskPreparationPublicPinsSha256 } from './bef-task-preparation.js';
import { HttpError } from './http-error.js';
import { evaluateTaskRubric, type EvaluateTaskInput, type TaskEvaluationResult, type TaskEvidenceBinding } from './task-evaluator.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import type { TaskPreparationAdapter, TaskPreparationRecord } from './task-preparation.js';
import { fenceTaskPreparationWithEvidence, getTaskPreparation } from './task-preparation.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type TaskCase, type TaskReleaseQuerySource } from './task-release.js';
import { readSealedTaskObservationBundle, sealTaskObservationBundle, type TaskObservationBundleCandidate } from './task-observation-store.js';
import { getTaskEvaluatorBuildHash, readRetainedTaskEvaluationInput, reconstructRetainedTaskEvaluation, recordTaskEvaluation,
  type StoredTaskEvaluation } from './task-result-service.js';
import { completeKnownTrainingRun, finalizeKnownTrainingTask, completeKnownRankedRun, finalizeKnownRankedTask } from './task-run-completion.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type TaskTarget = { runId: string; taskIndex: number };

export type TaskObservationMode = 'training' | 'ranked';
export type TaskObservationCollectorKind = 's1' | 's2' | 's4' | 'm1_training' | 'paid_data' | 'chain' | 's3' | 'composite';

/** Maps only collectors whose observation boundary is implemented for the selected run mode. */
export function taskObservationCollectorFor(mode: TaskObservationMode, taskId: string): TaskObservationCollectorKind | null {
  if (mode === 'training') {
    if (taskId === 'S1') return 's1';
    if (taskId === 'S2') return 's2';
    if (taskId === 'S4') return 's4';
    if (taskId === 'M1') return 'm1_training';
    if (taskId === 'H1') return 'paid_data';
    if (taskId === 'M3' || taskId === 'M4' || taskId === 'H2') return 'chain';
    return null;
  }
  if (mode === 'ranked') {
    if (taskId === 'S1') return 's1';
    if (taskId === 'S2') return 's2';
    if (taskId === 'S4') return 's4';
    if (taskId === 'S3') return 's3';
    if (taskId === 'H3' || taskId === 'U1') return 'composite';
    if (taskId === 'M1' || taskId === 'M2' || taskId === 'H1') return 'paid_data';
    if (taskId === 'M3' || taskId === 'M4' || taskId === 'H2') return 'chain';
  }
  return null;
}

export function supportsObservationTask(mode: TaskObservationMode, taskId: string): boolean {
  return taskObservationCollectorFor(mode, taskId) !== null;
}

export function supportsTrainingObservationTask(taskId: string): boolean {
  return supportsObservationTask('training', taskId);
}

export interface TaskTrainingObservationLifecycleDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
  repositoryRoot: string;
  /** Production wiring uses TaskSealedEvidenceSource; synthetic contract tests may supply a fixture-backed source. */
  evidenceSource: TaskEvaluationEvidenceSource;
  observerPorts: Pick<BefObservationPorts, 'postgresByEnvironment' | 'rpcByEnvironment' | 'evidenceSink'>;
  preparationAdapter: TaskPreparationAdapter;
  assertLeaseHeld(): Promise<void>;
}

/** Shared read-only dependencies accepted by the versioned observation collectors. */
export type TaskObservationCollectorDependencies = Pick<TaskTrainingObservationLifecycleDependencies,
  'db' | 'taskReleaseSource' | 'repositoryRoot' | 'observerPorts'>;

export type TaskTrainingObservationLifecycleStage = 'lease' | 'target' | 'observe' | 'preflight' | 'seal' |
  'reload' | 'evaluate' | 'fence' | 'fence_observation' | 'terminalize';

export type TaskTrainingObservationLifecycleResult =
  | { status: 'task_terminalized'; stage: 'terminalize'; runId: string; taskIndex: number; taskId: string;
      outcome: 'passed' | 'partial' | 'failed'; replayed: boolean }
  | { status: 'run_completed'; stage: 'terminalize'; runId: string; taskIndex: number; taskId: string;
      outcome: 'passed' | 'partial' | 'failed'; replayed: boolean }
  | { status: 'blocked' | 'unavailable'; stage: TaskTrainingObservationLifecycleStage; reasonCode: string;
      runId: string; taskIndex: number; taskId?: string; evaluationStatus?: 'known' | 'unknown' };

export type KnownCandidateSealResult<T> =
  | { status: 'known'; result: TaskEvaluationResult; sealed: T }
  | { status: 'unknown'; result: TaskEvaluationResult };

/** Keep incomplete candidates out of the immutable bundle store. */
export async function preflightAndSealKnownCandidate<T>(input: EvaluateTaskInput,
  seal: () => Promise<T>): Promise<KnownCandidateSealResult<T>> {
  const result = evaluateTaskRubric(input);
  if (result.status !== 'known') return { status: 'unknown', result };
  return { status: 'known', result, sealed: await seal() };
}

type CandidateResult = {
  status: 'candidate'; candidate: TaskObservationBundleCandidate; evidence: { path: string; sha256: string; boundary: 'actual_tool_http_x402_local_evm_application_store' };
  classification: 'run_bound_observations_candidate_not_grade';
};

type TargetRow = {
  owner_id: string; agent_id: string; mode: string; task_ids: string[]; run_status: string;
  cancellation_reason: string | null; cancellation_requested_at: Date | string | null;
  release_identity: string; manifest_hash: string; benchmark_hash: string; benchmark_version: string; policy_hash: string;
  task_id: string; task_status: string; closure_status: string; closure_id: string | null; closure_operation_id: string | null;
  closure_payload_hash: string | null; closure_reason: string | null; action_cutoff_sequence: string | number | null;
  reconciled_action_sequence: string | number; accepted_action_sequence: string | number;
  journal_closure_id: string | null; journal_owner_id: string | null; journal_agent_id: string | null;
  journal_operation_id: string | null; journal_payload_hash: string | null; journal_reason: string | null;
  journal_action_cutoff_sequence: string | number | null;
  preparation_id: string | null; claim_id: string | null; lease_id: string | null; environment_id: string | null;
  prep_release_identity: string | null; prep_manifest_hash: string | null; prep_task_id: string | null; case_id: string | null;
  case_hash: string | null; initial_state_sha256: string | null; execution_identity_hash: string | null;
  environment_manifest_sha256: string | null; application_source_hash: string | null; lease_state: string | null;
  preparation_status: string | null; generation_id: string | null; baseline_state_sha256: string | null;
  binding_env_id: string | null; binding_generation_id: string | null; binding_manifest_hash: string | null;
  binding_application_source_hash: string | null;
};

type CandidateContext = {
  taskId: string;
  selectedTaskCount: number;
  taskCase: TaskCase;
  input: EvaluateTaskInput;
  preparationId: string;
  generationId: string;
  environmentId: string;
};

type LifecycleTargetRow = {
  owner_id: string; agent_id: string; mode: string; task_ids: string[]; run_status: string;
  terminal_reason: string | null; cancellation_reason: string | null; cancellation_requested_at: Date | string | null;
  access_generation: number; agent_policy_revision: number; started_at: Date | string | null;
  overall_deadline: Date | string | null; finished_at: Date | string | null;
  task_id: string; task_status: string; task_closure_status: string; task_finished_at: Date | string | null;
};

type LifecycleTargetCheck = { row: LifecycleTargetRow } | { reasonCode: string; taskId?: string };

function blocked(target: TaskTarget, stage: TaskTrainingObservationLifecycleStage, reasonCode: string,
  taskId?: string, evaluationStatus?: 'known' | 'unknown'): TaskTrainingObservationLifecycleResult {
  return { status: 'blocked', stage, reasonCode, runId: target.runId, taskIndex: target.taskIndex,
    ...(taskId ? { taskId } : {}), ...(evaluationStatus ? { evaluationStatus } : {}) };
}

function unavailable(target: TaskTarget, stage: TaskTrainingObservationLifecycleStage, reasonCode: string,
  taskId?: string): TaskTrainingObservationLifecycleResult {
  return { status: 'unavailable', stage, reasonCode, runId: target.runId, taskIndex: target.taskIndex,
    ...(taskId ? { taskId } : {}) };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function safeErrorCode(error: unknown): string {
  const candidate = error instanceof HttpError ? error.code : '';
  return /^[A-Z][A-Z0-9_:-]{0,95}$/.test(candidate) ? candidate : 'lifecycle_dependency_unavailable';
}

function toSafeSequence(value: string | number | null): number | null {
  if (value === null) return null;
  try {
    const sequence = BigInt(value);
    return sequence >= 0n && sequence <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(sequence) : null;
  } catch { return null; }
}

function same(left: unknown, right: unknown): boolean { return canonicalTaskJson(left) === canonicalTaskJson(right); }

function validTimestamp(value: Date | string | null): boolean {
  return value !== null && Number.isFinite(value instanceof Date ? value.getTime() : Date.parse(value));
}

async function checkTrainingTarget(db: OwnerDatabase, target: TaskTarget): Promise<LifecycleTargetCheck> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION READ ONLY`);
    const rows = await tx.execute(sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.status AS run_status,r.terminal_reason,
        r.cancellation_reason,r.cancellation_requested_at,r.access_generation,r.agent_policy_revision,
        r.started_at,r.overall_deadline,r.finished_at,t.task_id,t.status AS task_status,
        t.closure_status AS task_closure_status,t.finished_at AS task_finished_at
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=${target.taskIndex}
      WHERE r.id=${target.runId}`) as unknown as LifecycleTargetRow[];
    const row = rows[0];
    if (!row) return { reasonCode: 'closed_training_task_not_current' };
    if (row.mode !== 'training' && row.mode !== 'ranked') return { reasonCode: 'training_run_required', taskId: row.task_id };
    if (row.mode === 'ranked' && !same(row.task_ids,TASK_IDS)) return {reasonCode:'ranked_full_task_set_required',taskId:row.task_id};
    if ((row.run_status !== 'running' && row.run_status !== 'completed') || row.terminal_reason !== null ||
        !validTimestamp(row.started_at) || !validTimestamp(row.overall_deadline) ||
        (row.run_status === 'running' && row.finished_at !== null) ||
        (row.run_status === 'completed' && !validTimestamp(row.finished_at))) {
      return { reasonCode: 'training_run_not_resumable', taskId: row.task_id };
    }
    if (row.cancellation_reason !== null || row.cancellation_requested_at !== null) {
      return { reasonCode: 'run_cancellation_history', taskId: row.task_id };
    }
    if (row.task_ids[target.taskIndex] !== row.task_id || !supportsObservationTask(row.mode as TaskObservationMode, row.task_id) ||
        row.task_closure_status !== 'closed' || !['active', 'completed', 'failed'].includes(row.task_status) ||
        ((row.task_status === 'completed' || row.task_status === 'failed') !== validTimestamp(row.task_finished_at)) ||
        (row.run_status === 'completed' && row.task_status !== 'completed' && row.task_status !== 'failed') ||
        (row.run_status === 'running' && row.task_status !== 'active' && target.taskIndex >= row.task_ids.length - 1)) {
      return { reasonCode: 'closed_training_task_not_current', taskId: row.task_id };
    }

    // Match the completion service's cancellation-history boundary before any retained-evidence
    // replay, evaluation, or external fence can occur. Completed-run replay ignores later events.
    const completedAt = row.run_status === 'completed' ? row.finished_at : null;
    const before = completedAt ? sql`AND created_at<=${completedAt}::timestamptz` : sql``;
    const history = await tx.execute(sql`SELECT
        EXISTS(SELECT 1 FROM oid_agent_cancellation_outbox c WHERE c.owner_id=${row.owner_id} AND c.agent_id=${row.agent_id}
          AND c.access_generation>${row.access_generation} ${before}) AS revoked,
        EXISTS(SELECT 1 FROM oid_run_mode_cancellation_outbox c WHERE c.owner_id=${row.owner_id} AND c.agent_id=${row.agent_id}
          AND c.mode=${row.mode} AND c.policy_revision>${row.agent_policy_revision} ${before}) AS mode_removed,
        EXISTS(SELECT 1 FROM oid_run_cancellation_receipt c WHERE (${target.runId}=ANY(c.cancelled_run_ids) OR ${target.runId}=ANY(c.pending_run_ids))
          ${completedAt ? sql`AND c.created_at<=${completedAt}::timestamptz` : sql``}) AS receipt,
        EXISTS(SELECT 1 FROM oid_run_outbox c WHERE c.run_id=${target.runId} AND c.event_type='run.cancel.requested' ${before}) AS pending_cancel`) as
      Array<{ revoked: boolean; mode_removed: boolean; receipt: boolean; pending_cancel: boolean }>;
    const cancellation = history[0];
    if (cancellation?.revoked || cancellation?.mode_removed || cancellation?.receipt || cancellation?.pending_cancel) {
      return { reasonCode: 'run_cancellation_history', taskId: row.task_id };
    }
    return { row };
  });
}

function preparationMatchesSealed(preparation: TaskPreparationRecord,
  sealed: NonNullable<Awaited<ReturnType<typeof readSealedTaskObservationBundle>>>, target: TaskTarget): boolean {
  const bundle = sealed.bundle;
  const intent = preparation.intent;
  const generationId = bundle.execution.generationId.toLowerCase();
  return intent.preparationId.toLowerCase() === bundle.execution.preparationId.toLowerCase() &&
    intent.leaseId.toLowerCase() === bundle.execution.leaseId.toLowerCase() &&
    intent.runId.toLowerCase() === target.runId.toLowerCase() && intent.taskIndex === target.taskIndex &&
    intent.taskId === bundle.binding.taskId && intent.environmentId === bundle.binding.environmentId &&
    intent.releaseIdentity === bundle.binding.releaseIdentity && intent.manifestHash === bundle.binding.manifestHash &&
    intent.caseId === bundle.binding.caseId && intent.caseHash === bundle.binding.caseHash &&
    intent.initialStateSha256 === bundle.execution.initialStateSha256 &&
    intent.executionIdentityHash === bundle.execution.executionIdentityHash &&
    intent.environmentManifestSha256 === bundle.execution.environmentManifestHash &&
    intent.applicationSourceHash === bundle.execution.applicationSourceHash &&
    preparation.observation.generationId?.toLowerCase() === generationId &&
    ((preparation.leaseStatus === 'leased' && preparation.observation.status === 'ready') ||
      (preparation.leaseStatus === 'fenced' && preparation.observation.status === 'fenced'));
}

async function loadCandidateContext(deps: TaskTrainingObservationLifecycleDependencies, target: TaskTarget,
  candidate: TaskObservationBundleCandidate): Promise<CandidateContext | null> {
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION READ ONLY`);
    const rows = await tx.execute(sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.status AS run_status,
        r.cancellation_reason,r.cancellation_requested_at,r.release_identity,r.manifest_hash,r.benchmark_hash,r.benchmark_version,r.policy_hash,
        t.task_id,t.status AS task_status,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
        t.action_cutoff_sequence::text AS action_cutoff_sequence,t.reconciled_action_sequence::text AS reconciled_action_sequence,
        t.accepted_action_sequence::text AS accepted_action_sequence,
        c.id AS journal_closure_id,c.owner_id AS journal_owner_id,c.agent_id AS journal_agent_id,c.operation_id AS journal_operation_id,
        c.payload_hash AS journal_payload_hash,c.reason AS journal_reason,c.action_cutoff_sequence::text AS journal_action_cutoff_sequence,
        i.preparation_id::text AS preparation_id,i.claim_id::text AS claim_id,i.lease_id::text AS lease_id,i.environment_id,
        i.release_identity AS prep_release_identity,i.manifest_hash AS prep_manifest_hash,i.task_id AS prep_task_id,i.case_id,i.case_hash,
        i.initial_state_sha256,i.execution_identity_hash,i.environment_manifest_sha256,i.application_source_hash,
        l.state AS lease_state,o.status AS preparation_status,o.generation_id::text AS generation_id,o.baseline_state_sha256,
        eb.env_id AS binding_env_id,eb.generation_id::text AS binding_generation_id,eb.manifest_hash AS binding_manifest_hash,
        eb.application_source_hash AS binding_application_source_hash
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=${target.taskIndex}
      LEFT JOIN oid_run_task_closure c ON c.id=t.closure_id AND c.run_id=r.id AND c.task_index=t.task_index
      LEFT JOIN oid_task_preparation_intent i ON i.run_id=r.id AND i.task_index=t.task_index
      LEFT JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      LEFT JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256 FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
      LEFT JOIN oid_task_execution_binding eb ON eb.run_id=r.id AND eb.task_index=t.task_index
      WHERE r.id=${target.runId}`) as unknown as TargetRow[];
    const row = rows[0];
    if (!row || (row.mode !== 'training' && row.mode !== 'ranked') || row.task_ids[target.taskIndex] !== row.task_id ||
        !supportsObservationTask(row.mode as TaskObservationMode, row.task_id) || row.run_status !== 'running' || row.task_status !== 'active' ||
        row.cancellation_reason !== null || row.cancellation_requested_at !== null || row.closure_status !== 'closed' ||
        !row.closure_id || !row.preparation_id || !row.lease_id || !row.environment_id || !row.generation_id ||
        !row.case_id || !row.case_hash || !row.initial_state_sha256 || !row.execution_identity_hash ||
        !row.environment_manifest_sha256 || !row.application_source_hash || row.lease_state !== 'leased' ||
        row.preparation_status !== 'ready' || row.baseline_state_sha256 !== row.initial_state_sha256 ||
        row.prep_release_identity !== row.release_identity || row.prep_manifest_hash !== row.manifest_hash ||
        row.prep_task_id !== row.task_id || row.binding_env_id !== row.environment_id ||
        row.binding_generation_id !== row.generation_id || row.binding_manifest_hash !== row.environment_manifest_sha256 ||
        row.binding_application_source_hash !== row.application_source_hash) return null;
    const actionCutoff = toSafeSequence(row.action_cutoff_sequence);
    const reconciled = toSafeSequence(row.reconciled_action_sequence);
    const accepted = toSafeSequence(row.accepted_action_sequence);
    const journalCutoff = toSafeSequence(row.journal_action_cutoff_sequence);
    if (actionCutoff === null || reconciled === null || accepted !== actionCutoff || journalCutoff !== actionCutoff ||
        reconciled < actionCutoff || row.journal_closure_id !== row.closure_id || row.journal_owner_id !== row.owner_id ||
        row.journal_agent_id !== row.agent_id || row.journal_operation_id !== row.closure_operation_id ||
        row.journal_payload_hash !== row.closure_payload_hash || row.journal_reason !== row.closure_reason) return null;
    const release = await deps.taskReleaseSource.getValidatedReleaseRecord(row.release_identity, row.manifest_hash, tx);
    if (!release || release.releaseIdentity !== row.release_identity || release.manifestHash !== row.manifest_hash ||
        release.benchmarkHash !== row.benchmark_hash || release.benchmarkVersion !== row.benchmark_version ||
        release.policyHash !== row.policy_hash || release.manifest.releaseIdentity !== row.release_identity ||
        release.manifest.manifestHash !== row.manifest_hash) return null;
    const taskCase = release.manifest.cases[row.mode as TaskObservationMode].find((entry) => entry.taskId === row.task_id);
    if (!taskCase || taskCase.caseId !== row.case_id || taskCase.caseHash !== row.case_hash ||
        taskCase.executionIdentityHash !== row.execution_identity_hash ||
        taskCase.initialState.stateSha256 !== row.initial_state_sha256 ||
        release.manifest.executionIdentity.environmentManifestSha256 !== row.environment_manifest_sha256 ||
        release.manifest.executionIdentity.x402ServiceSha256 !== row.application_source_hash) return null;
    if (candidate.cutoffStatus !== 'authoritative' || !candidate.cutoffEvidence || !candidate.observations) return null;
    const binding: TaskEvidenceBinding = {
      ownerId: row.owner_id, agentId: row.agent_id, runId: target.runId, environmentId: row.environment_id,
      releaseIdentity: row.release_identity, manifestHash: row.manifest_hash, caseId: taskCase.caseId,
      caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: taskCase.taskId,
    };
    const input: EvaluateTaskInput = {
      taskCase,
      release: release.manifest,
      run: { ...binding, acceptedActionCutoffSequence: actionCutoff, reconciledThroughActionSequence: reconciled,
        observationCutoffSequence: candidate.observationCutoffSequence, cutoffStatus: 'authoritative',
        cutoffEvidence: candidate.cutoffEvidence },
      observations: candidate.observations,
    };
    return { taskId: row.task_id, selectedTaskCount: row.task_ids.length, taskCase, input,
      preparationId: row.preparation_id, generationId: row.generation_id, environmentId: row.environment_id };
  });
}

async function loadSealedInput(deps: TaskTrainingObservationLifecycleDependencies, target: TaskTarget,
  closureId: string): Promise<EvaluateTaskInput | null> {
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION READ ONLY`);
    return deps.evidenceSource.load({ runId: target.runId, taskIndex: target.taskIndex, closureId }, tx);
  });
}

async function hasTaskEvaluation(db: OwnerDatabase, target: TaskTarget): Promise<boolean> {
  const rows = await db.execute(sql`SELECT 1 AS present FROM oid_run_task_evaluation WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as Array<{ present: number }>;
  return rows.length > 0;
}

export async function collectObservationCandidate(deps: TaskObservationCollectorDependencies, target: TaskTarget,
  mode: TaskObservationMode, taskId: string) {
  // AICODE-NOTE: Existing collectors own their bounded snapshot transactions; this lifecycle adds no enclosing
  // transaction around observer calls. Their current owner/run lock duration is a collector-level limitation.
  const common = { db: deps.db, taskReleaseSource: deps.taskReleaseSource, repositoryRoot: deps.repositoryRoot,
    postgresByEnvironment: deps.observerPorts.postgresByEnvironment,
    rpcByEnvironment: deps.observerPorts.rpcByEnvironment, evidenceSink: deps.observerPorts.evidenceSink };
  switch (taskObservationCollectorFor(mode, taskId)) {
    case 's1': return collectBefS1TaskObservationCandidate(common, target);
    case 's2': return collectBefS2TaskObservationCandidate(common, target);
    case 's4': return collectBefS4TaskObservationCandidate(common, target);
    case 'm1_training': return collectBefM1TaskObservationCandidate(common, target);
    case 'paid_data': return collectBefPaidDataObservationCandidate(common, target);
    case 'chain': return collectBefChainTaskObservationCandidate(common, target);
    case 's3': return collectBefS3TaskObservationCandidate(common, target);
    case 'composite': return collectBefCompositeObservationCandidate(common, target);
    default: return { status: 'unavailable' as const, reasonCode: 'unsupported_task' };
  }
}


function isCandidate(value: unknown): value is CandidateResult {
  return isRecord(value) && value.status === 'candidate' && value.classification === 'run_bound_observations_candidate_not_grade' &&
    isRecord(value.candidate) && value.candidate.schemaVersion === 'bts-task-observation-bundle-candidate/v1' &&
    isRecord(value.evidence) && typeof value.evidence.path === 'string' && typeof value.evidence.sha256 === 'string' &&
    value.evidence.boundary === 'actual_tool_http_x402_local_evm_application_store';
}

export function verifyFencedPreparation(preparation: TaskPreparationRecord,
  sealed: NonNullable<Awaited<ReturnType<typeof readSealedTaskObservationBundle>>>, proof: BefFenceProof, target: TaskTarget): boolean {
  const bundle = sealed.bundle;
  const intent = preparation.intent;
  const generationId = bundle.execution.generationId.toLowerCase();
  if (!preparationMatchesSealed(preparation, sealed, target) || preparation.leaseStatus !== 'fenced' ||
      preparation.observation.status !== 'fenced') return false;
  const generation = proof.generation;
  const observed = proof.preparation;
  return Boolean(generation && observed && generation.generation_id.toLowerCase() === generationId &&
    generation.env_id === intent.environmentId && generation.status === 'fenced' && generation.fenced_at &&
    Number.isFinite(Date.parse(generation.fenced_at)) && observed.preparation_id.toLowerCase() === intent.preparationId.toLowerCase() &&
    observed.status === 'fenced' && observed.fence_confirmed_at && Number.isFinite(Date.parse(observed.fence_confirmed_at)) &&
    observed.preparation_generation_id.toLowerCase() === generationId &&
    observed.public_pins_sha256.toLowerCase() === taskPreparationPublicPinsSha256(intent).toLowerCase() &&
    observed.manifest_sha256.toLowerCase() === intent.environmentManifestSha256.toLowerCase() &&
    observed.environment_manifest_hash.toLowerCase() === intent.environmentManifestSha256.toLowerCase());
}

async function observeFencedPreparation(deps: TaskTrainingObservationLifecycleDependencies, preparation: TaskPreparationRecord,
  sealed: NonNullable<Awaited<ReturnType<typeof readSealedTaskObservationBundle>>>, target: TaskTarget): Promise<boolean> {
  const port = deps.observerPorts.postgresByEnvironment[preparation.intent.environmentId];
  if (!port || port.environmentId !== preparation.intent.environmentId) return false;
  await deps.assertLeaseHeld();
  const proof = await port.readFenceProof({ preparationId: preparation.intent.preparationId,
    generationId: sealed.bundle.execution.generationId });
  await deps.assertLeaseHeld();
  return verifyFencedPreparation(preparation, sealed, proof, target) &&
    preparation.intent.runId.toLowerCase() === target.runId.toLowerCase() && preparation.intent.taskIndex === target.taskIndex;
}

function evaluationOutcome(evaluation: StoredTaskEvaluation): 'passed' | 'partial' | 'failed' | null {
  if (evaluation.result.status !== 'known' ||
      (evaluation.result.outcome !== 'passed' && evaluation.result.outcome !== 'partial' && evaluation.result.outcome !== 'failed')) return null;
  return evaluation.result.outcome;
}

/**
 * Processes one closed training task through immutable observation, known rubric result,
 * original-generation fence, independent BEF fence proof, and normal task/run completion.
 * It never executes participant actions or changes charge, deadline, or unknown-result policy.
 */
export async function processClosedTrainingTask(
  deps: TaskTrainingObservationLifecycleDependencies,
  input: TaskTarget,
): Promise<TaskTrainingObservationLifecycleResult> {
  const target = { runId: input.runId.toLowerCase(), taskIndex: input.taskIndex };
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(target.runId) ||
      !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) {
    return unavailable(target, 'target', 'invalid_task_target');
  }
  let stage: TaskTrainingObservationLifecycleStage = 'lease';
  let taskId: string | undefined;
  try {
    await deps.assertLeaseHeld();
    stage = 'target';
    const targetCheck = await checkTrainingTarget(deps.db, target);
    await deps.assertLeaseHeld();
    if (!('row' in targetCheck)) return blocked(target, stage, targetCheck.reasonCode, targetCheck.taskId);
    taskId = targetCheck.row.task_id;
    let sealed = await readSealedTaskObservationBundle(deps.db, target);
    await deps.assertLeaseHeld();
    if (!sealed) {
      if (await hasTaskEvaluation(deps.db, target)) return blocked(target, 'target', 'evaluation_without_sealed_observation_bundle');
      if (targetCheck.row.run_status !== 'running' || targetCheck.row.task_status !== 'active') {
        return blocked(target, 'target', 'closed_training_task_not_current', taskId);
      }
      stage = 'observe';
      await deps.assertLeaseHeld();
      const collection = await collectObservationCandidate(deps, target, targetCheck.row.mode as TaskObservationMode, taskId);
      await deps.assertLeaseHeld();
      if (!isCandidate(collection)) {
        const collectionValue: unknown = collection;
        const reasonCode = isRecord(collectionValue) ? collectionValue.reasonCode : null;
        const reason = typeof reasonCode === 'string' && /^[a-z0-9_]{1,80}$/.test(reasonCode)
          ? reasonCode : 'observation_unavailable';
        return blocked(target, stage, reason, taskId);
      }
      stage = 'preflight';
      const context = await loadCandidateContext(deps, target, collection.candidate);
      await deps.assertLeaseHeld();
      if (!context) return blocked(target, stage, 'candidate_binding_or_cutoff_unavailable', taskId);
      await deps.assertLeaseHeld();
      stage = 'seal';
      const gated = await preflightAndSealKnownCandidate(context.input, () =>
        sealTaskObservationBundle({ db: deps.db, taskReleaseSource: deps.taskReleaseSource }, target, collection.candidate));
      await deps.assertLeaseHeld();
      if (gated.status !== 'known') return blocked(target, 'preflight', 'candidate_evaluation_unknown', taskId, 'unknown');
      const stored = gated.sealed;
      if (stored.status !== 'sealed') return blocked(target, stage, stored.reasonCode, taskId);
      sealed = stored;
      if (sha256CanonicalTaskJson(sealed.bundle.observations) !== sha256CanonicalTaskJson(collection.candidate.observations) ||
          sealed.bundleHash !== sha256CanonicalTaskJson(sealed.bundle)) {
        return blocked(target, stage, 'sealed_candidate_binding_conflict', taskId);
      }
      const preflightInputHash = sha256CanonicalTaskJson(context.input);
      const sealedInput = await loadSealedInput(deps, target, sealed.bundle.closure.closureId);
      if (!sealedInput) return blocked(target, 'reload', 'sealed_evidence_unavailable', taskId);
      if (sha256CanonicalTaskJson(sealedInput) !== preflightInputHash || evaluateTaskRubric(sealedInput).status !== 'known') {
        return blocked(target, 'reload', 'sealed_candidate_preflight_mismatch', taskId);
      }
    }

    taskId = sealed.bundle.binding.taskId;
    stage = 'reload';
    const exactInput = await loadSealedInput(deps, target, sealed.bundle.closure.closureId);
    await deps.assertLeaseHeld();
    if (!exactInput) return blocked(target, stage, 'sealed_evidence_unavailable', taskId);
    const exactInputHash = sha256CanonicalTaskJson(exactInput);
    let evaluation: StoredTaskEvaluation;
    stage = 'evaluate';
    if (await hasTaskEvaluation(deps.db, target)) {
      const [retained, reconstructed] = await Promise.all([
        readRetainedTaskEvaluationInput(deps.db, target),
        reconstructRetainedTaskEvaluation(deps.db, target),
      ]);
      await deps.assertLeaseHeld();
      if (reconstructed.diverged || retained.closureId !== sealed.bundle.closure.closureId ||
          retained.inputHash !== exactInputHash || !same(retained.input, exactInput) ||
          reconstructed.original.inputHash !== exactInputHash) {
        return blocked(target, stage, 'retained_evaluation_reconstruction_mismatch', taskId);
      }
      evaluation = reconstructed.original;
    } else {
      const result = evaluateTaskRubric(exactInput);
      if (result.status !== 'known') return blocked(target, stage, 'sealed_evaluation_unknown', taskId, 'unknown');
      await deps.assertLeaseHeld();
      const recorded = await recordTaskEvaluation({ db: deps.db, taskReleaseSource: deps.taskReleaseSource,
        evidenceSource: deps.evidenceSource, evaluatorSourceHash: await getTaskEvaluatorBuildHash() }, target);
      await deps.assertLeaseHeld();
      if (recorded.evaluation.inputHash !== exactInputHash || recorded.evaluation.closureId !== sealed.bundle.closure.closureId) {
        return blocked(target, stage, 'recorded_evaluation_binding_mismatch', taskId);
      }
      evaluation = recorded.evaluation;
    }
    const outcome = evaluationOutcome(evaluation);
    if (!outcome) return blocked(target, stage, 'task_evaluation_not_known', taskId, 'unknown');

    stage = 'fence';
    await deps.assertLeaseHeld();
    const preparation = await getTaskPreparation(deps.db, sealed.bundle.execution.preparationId);
    if (!preparation || !preparationMatchesSealed(preparation, sealed, target) || preparation.intent.taskId !== taskId) {
      return blocked(target, stage, 'original_preparation_identity_unavailable', taskId);
    }
    const fence = await fenceTaskPreparationWithEvidence({ db: deps.db, preparationAdapter: deps.preparationAdapter },
      preparation.intent.preparationId, sealed.bundle.execution.generationId);
    await deps.assertLeaseHeld();
    if (!fence.released) return blocked(target, stage, 'original_generation_fence_unconfirmed', taskId);
    const fencedPreparation = await getTaskPreparation(deps.db, preparation.intent.preparationId);
    if (!fencedPreparation) return blocked(target, stage, 'fenced_preparation_unavailable', taskId);

    stage = 'fence_observation';
    if (!await observeFencedPreparation(deps, fencedPreparation, sealed, target)) {
      return blocked(target, stage, 'independent_bef_fence_proof_unavailable', taskId);
    }

    stage = 'terminalize';
    await deps.assertLeaseHeld();
    const countRows = await deps.db.execute(sql`SELECT task_ids FROM oid_benchmark_run WHERE id=${target.runId}`) as unknown as Array<{ task_ids: string[] }>;
    const selectedCount = countRows[0]?.task_ids.length;
    if (!selectedCount || target.taskIndex >= selectedCount) return blocked(target, stage, 'selected_task_set_unavailable', taskId);
    if (target.taskIndex === selectedCount - 1) {
      const completed = await (targetCheck.row.mode === 'ranked' ? completeKnownRankedRun : completeKnownTrainingRun)({ db: deps.db, taskReleaseSource: deps.taskReleaseSource,
        evidenceSource: deps.evidenceSource }, { runId: target.runId });
      await deps.assertLeaseHeld();
      return { status: 'run_completed', stage, runId: target.runId, taskIndex: target.taskIndex, taskId,
        outcome, replayed: completed.replayed };
    }
    const finalized = await (targetCheck.row.mode === 'ranked' ? finalizeKnownRankedTask : finalizeKnownTrainingTask)({ db: deps.db, taskReleaseSource: deps.taskReleaseSource,
      evidenceSource: deps.evidenceSource }, target);
    await deps.assertLeaseHeld();
    return { status: 'task_terminalized', stage, runId: target.runId, taskIndex: target.taskIndex, taskId,
      outcome, replayed: finalized.replayed };
  } catch (error) {
    return unavailable(target, stage, safeErrorCode(error), taskId);
  }
}
