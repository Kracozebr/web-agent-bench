import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import type { PersistedObservationMeta, PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseQuerySource } from './task-release.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const EVIDENCE_PATH = /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature',
]);

/** One final candidate for a closure; the store has no append/revision operation. */
export type TaskObservationBundleCandidate = {
  schemaVersion: 'bts-task-observation-bundle-candidate/v1';
  observationCutoffSequence: number;
  cutoffStatus: 'authoritative' | 'unknown' | 'contradictory';
  cutoffEvidence: EvidenceReference | null;
  observations: PersistedTaskObservations | null;
};

export type SealedTaskObservationBundle = {
  schemaVersion: 'bts-task-observation-bundle/v1';
  binding: TaskEvidenceBinding;
  closure: {
    closureId: string;
    operationId: string | null;
    payloadHash: string;
    reason: 'agent_finish' | 'task_deadline' | 'run_deadline';
    actionCutoffSequence: number;
    reconciledActionSequence: number;
  };
  execution: {
    preparationId: string;
    leaseId: string;
    generationId: string;
    environmentManifestHash: string;
    applicationSourceHash: string;
    executionIdentityHash: string;
    initialStateSha256: string;
  };
  cutoff: {
    observationSequence: number;
    status: 'authoritative';
    evidence: EvidenceReference;
  };
  observations: PersistedTaskObservations;
};

export type TaskObservationStoreResult =
  | { status: 'unavailable'; reasonCode: 'cutoff_unknown' | 'cutoff_contradictory' | 'observations_missing' | 'cutoff_evidence_missing' }
  | { status: 'sealed'; bundleHash: string; bundle: SealedTaskObservationBundle; createdAt: string; replayed: boolean };

export interface TaskObservationStoreDependencies {
  db: OwnerDatabase;
  taskReleaseSource: TaskReleaseQuerySource;
}

type RunTaskRow = {
  owner_id: string; agent_id: string; mode: 'training' | 'ranked'; task_ids: string[];
  status: string; release_identity: string; manifest_hash: string;
  task_id: string; task_status: string; closure_status: string; closure_id: string | null;
  closure_operation_id: string | null; closure_payload_hash: string | null; closure_reason: 'agent_finish' | 'task_deadline' | 'run_deadline' | null;
  action_cutoff_sequence: string | number | null; reconciled_action_sequence: string | number;
};

type ClosureRow = {
  id: string; operation_id: string | null; payload_hash: string; reason: 'agent_finish' | 'task_deadline' | 'run_deadline';
  action_cutoff_sequence: string | number; owner_id: string; agent_id: string;
};

type PreparationRow = {
  preparation_id: string; lease_id: string; environment_id: string; release_identity: string; manifest_hash: string;
  task_id: string; case_id: string; case_hash: string; initial_state_sha256: string;
  environment_manifest_sha256: string; application_source_hash: string; execution_identity_hash: string;
  lease_state: 'leased' | 'fenced'; observation_status: string; generation_id: string | null;
  baseline_state_sha256: string | null;
};

type ExecutionBindingRow = {
  env_id: string; generation_id: string; manifest_hash: string; application_source_hash: string;
};

type StoredRow = {
  bundle_hash: string; bundle_json: SealedTaskObservationBundle | string; created_at: Date | string;
};

function fail(status: number, code: string, message: string): never {
  throw new HttpError(status, code, message);
}

function validateTarget(runId: string, taskIndex: number): void {
  if (!UUID.test(runId) || !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11) {
    fail(400, 'INVALID_TASK_OBSERVATION_TARGET', 'A run UUID and bounded task index are required');
  }
}

function sequence(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  try {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(parsed);
  } catch { return null; }
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}

function validEvidence(value: unknown): value is EvidenceReference {
  if (!plainObject(value) || Object.keys(value).sort().join(',') !== 'boundary,path,sha256') return false;
  return typeof value.path === 'string' && EVIDENCE_PATH.test(value.path) &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256) &&
    value.boundary === 'actual_tool_http_x402_local_evm_application_store';
}

function assertJsonAndNoSecrets(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Observation data must be finite JSON');
    return;
  }
  if (typeof value !== 'object') fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Observation data must contain JSON values only');
  if (ancestors.has(value)) fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Observation data cannot be cyclic');
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      if (plainObject(item) && typeof item.name === 'string' &&
          SECRET_KEYS.has(item.name.toLowerCase().replace(/[^a-z]/g, ''))) {
        fail(400, 'TASK_OBSERVATION_SECRET_FIELD', 'Credential-like payment fields cannot be retained in task observations');
      }
      assertJsonAndNoSecrets(item, ancestors);
    }
  } else {
    if (!plainObject(value)) fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Observation objects must be plain JSON objects');
    for (const [key, item] of Object.entries(value)) {
      const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
      if (SECRET_KEYS.has(normalized)) fail(400, 'TASK_OBSERVATION_SECRET_FIELD', 'Secret material cannot be retained in task observations');
      assertJsonAndNoSecrets(item, ancestors);
    }
  }
  ancestors.delete(value);
}

function sameBinding(left: TaskEvidenceBinding, right: TaskEvidenceBinding): boolean {
  return left.ownerId === right.ownerId && left.agentId === right.agentId && left.runId === right.runId &&
    left.environmentId === right.environmentId && left.releaseIdentity === right.releaseIdentity &&
    left.manifestHash === right.manifestHash && left.caseId === right.caseId && left.caseHash === right.caseHash &&
    left.rubricHash === right.rubricHash && left.taskId === right.taskId;
}

function expectedBinding(row: RunTaskRow, runId: string, environmentId: string, caseId: string, taskCase: TaskCase): TaskEvidenceBinding {
  if (!environmentId) fail(503, 'TASK_OBSERVATION_EXECUTION_BINDING_UNAVAILABLE', 'The task has no pinned environment');
  return {
    ownerId: row.owner_id,
    agentId: row.agent_id,
    runId,
    environmentId,
    releaseIdentity: row.release_identity,
    manifestHash: row.manifest_hash,
    caseId,
    caseHash: taskCase.caseHash,
    rubricHash: taskCase.rubricHash,
    taskId: row.task_id as TaskEvidenceBinding['taskId'],
  };
}

function validateObservationPayload(
  observations: PersistedTaskObservations,
  binding: TaskEvidenceBinding,
  observationCutoffSequence: number,
  actionCutoffSequence: number,
): number[] {
  const topLevelKeys = ['schemaVersion', 'binding', 'coveredThroughSequence', 'captureEvidence', 'coverage', 'transfers', 'payments',
    'stateMutations', 'finalStates', 'allowanceChanges', 'allowanceUses', 'answers', 'selections', 'deliveries', 'trades', 'conversions', 'expenses'];
  if (!plainObject(observations) || Object.keys(observations).some((key) => !topLevelKeys.includes(key)) ||
      observations.schemaVersion !== 'bts-task-observations/v1' || !sameBinding(observations.binding, binding) ||
      observations.coveredThroughSequence !== observationCutoffSequence || !validEvidence(observations.captureEvidence) ||
      !plainObject(observations.coverage)) {
    fail(409, 'TASK_OBSERVATION_CUTOFF_MISMATCH', 'Observation bundle does not identify one exact, hash-backed cutoff');
  }

  const domains = new Set(['transfers', 'payments', 'stateMutations', 'balances', 'allowances', 'answers', 'selections', 'deliveries',
    'trades', 'conversions', 'expenses']);
  for (const [domain, coverage] of Object.entries(observations.coverage)) {
    if (!domains.has(domain) || !['complete', 'incomplete', 'contradictory'].includes(String(coverage))) {
      fail(400, 'INVALID_TASK_OBSERVATION_COVERAGE', 'Observation coverage must preserve the declared typed states');
    }
  }

  const eventKinds: Array<[keyof PersistedTaskObservations, string]> = [
    ['transfers', 'transfer'], ['payments', 'payment'], ['stateMutations', 'state_mutation'], ['finalStates', 'final_state'],
    ['allowanceChanges', 'allowance_change'], ['allowanceUses', 'allowance_use'], ['answers', 'final_answer'],
    ['selections', 'offer_selection'], ['deliveries', 'data_delivery'], ['trades', 'trade'], ['conversions', 'conversion'], ['expenses', 'expense'],
  ];
  const actionSequences = new Set<number>();
  for (const [field, kind] of eventKinds) {
    const entries = observations[field];
    if (!Array.isArray(entries)) fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Every typed observation domain must be an array');
    const observationIds = new Set<string>();
    for (const entry of entries) {
      const event = entry as unknown as PersistedObservationMeta & { kind?: string };
      if (!plainObject(event) || event.kind !== kind || !event.observationId || typeof event.observationId !== 'string' ||
          !Number.isSafeInteger(event.sequence) || event.sequence < 0 || event.sequence > observationCutoffSequence ||
          !Number.isSafeInteger(event.actionSequence) || event.actionSequence < 0 || event.actionSequence > actionCutoffSequence ||
          event.source !== 'persisted_observer' || !sameBinding(event.binding, binding) || !validEvidence(event.evidence)) {
        fail(409, 'TASK_OBSERVATION_OUTSIDE_CUTOFF', 'A typed observation is malformed, foreign, or after its immutable action/observation cutoff');
      }
      if (observationIds.has(event.observationId)) {
        fail(409, 'TASK_OBSERVATION_DUPLICATE_ID', 'Observation IDs must be unique within each typed domain');
      }
      observationIds.add(event.observationId);
      // Zero is retained for snapshots/cutoff observations that have no admitted action.
      if (event.actionSequence > 0) actionSequences.add(event.actionSequence);
    }
  }
  assertJsonAndNoSecrets(observations);
  return [...actionSequences];
}

function jsonValue<T>(value: T | string): T {
  return typeof value === 'string' ? JSON.parse(value) as T : value;
}

function storedRecord(row: StoredRow, expectedHash?: string): TaskObservationStoreResult & { status: 'sealed' } {
  const bundle = jsonValue(row.bundle_json);
  const calculatedHash = sha256CanonicalTaskJson(bundle);
  if (calculatedHash !== row.bundle_hash || (expectedHash !== undefined && row.bundle_hash !== expectedHash)) {
    fail(409, 'TASK_OBSERVATION_HASH_CONFLICT', 'A different immutable observation bundle is already retained for this task');
  }
  assertJsonAndNoSecrets(bundle);
  return { status: 'sealed', bundleHash: row.bundle_hash, bundle, createdAt: new Date(row.created_at).toISOString(), replayed: true };
}

/**
 * Seal one final caller-verified bundle for a closure. Incomplete coverage is
 * retained exactly as supplied; a different later bundle conflicts, so a caller
 * must finish reconciliation before the final seal. There is no append/revision
 * path. The caller owns raw HTTP, PostgreSQL, and RPC collection; this store
 * never calls BEF, derives coverage, or grades.
 */
export async function sealTaskObservationBundle(
  deps: TaskObservationStoreDependencies,
  target: { runId: string; taskIndex: number },
  candidate: TaskObservationBundleCandidate,
): Promise<TaskObservationStoreResult> {
  validateTarget(target.runId, target.taskIndex);
  let frozenCandidate: TaskObservationBundleCandidate;
  try { frozenCandidate = structuredClone(candidate); }
  catch { fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'Observation data must be cloneable JSON'); }
  if (frozenCandidate.schemaVersion !== 'bts-task-observation-bundle-candidate/v1') {
    fail(400, 'INVALID_TASK_OBSERVATION_BUNDLE', 'The observation candidate schema is unsupported');
  }
  if (frozenCandidate.cutoffStatus === 'unknown') return { status: 'unavailable', reasonCode: 'cutoff_unknown' };
  if (frozenCandidate.cutoffStatus === 'contradictory') return { status: 'unavailable', reasonCode: 'cutoff_contradictory' };
  if (frozenCandidate.cutoffStatus !== 'authoritative') {
    fail(400, 'INVALID_TASK_OBSERVATION_CUTOFF', 'An authoritative observation cutoff is required before sealing');
  }
  if (!frozenCandidate.observations) return { status: 'unavailable', reasonCode: 'observations_missing' };
  if (!validEvidence(frozenCandidate.cutoffEvidence)) return { status: 'unavailable', reasonCode: 'cutoff_evidence_missing' };
  if (!Number.isSafeInteger(frozenCandidate.observationCutoffSequence) || frozenCandidate.observationCutoffSequence < 0) {
    fail(400, 'INVALID_TASK_OBSERVATION_CUTOFF', 'An exact nonnegative observation sequence is required');
  }
  const observations = frozenCandidate.observations;
  const cutoffEvidence = frozenCandidate.cutoffEvidence;

  return deps.db.transaction(async (tx) => {
    const ownerRows = await tx.execute(sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${target.runId}`) as unknown as Array<{
      owner_id: string; agent_id: string;
    }>;
    if (!ownerRows[0]) fail(404, 'RUN_NOT_FOUND', 'The task observation run does not exist');

    // AICODE-NOTE: This conservative first write requires a leased DB row. The row lock serializes
    // the seal with committed lease fencing; the caller still owns raw-source verification, and
    // this store does not serialize an external reset that begins before its DB fence transition.
    // Match the lifecycle services: owner, agent, run/task, then the preparation lease.
    await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${ownerRows[0].owner_id} FOR NO KEY UPDATE`);
    await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${ownerRows[0].agent_id} AND owner_id=${ownerRows[0].owner_id} FOR NO KEY UPDATE`);
    const runRows = await tx.execute(sql`SELECT r.owner_id,r.agent_id,r.mode,r.task_ids,r.status,r.release_identity,r.manifest_hash,
        t.task_id,t.status AS task_status,t.closure_status,t.closure_id,t.closure_operation_id,t.closure_payload_hash,t.closure_reason,
        t.action_cutoff_sequence,t.reconciled_action_sequence
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
      WHERE r.id=${target.runId} AND r.owner_id=${ownerRows[0].owner_id} AND r.agent_id=${ownerRows[0].agent_id}
        AND t.task_index=${target.taskIndex} FOR UPDATE OF r,t`) as unknown as RunTaskRow[];
    const run = runRows[0];
    if (!run) fail(404, 'TASK_NOT_FOUND', 'The task does not exist');
    if (run.closure_status !== 'closed' || !run.closure_id || run.action_cutoff_sequence === null) {
      fail(409, 'TASK_OBSERVATION_CLOSURE_UNAVAILABLE', 'Only a closed task with an immutable action cutoff can be observed');
    }
    const actionCutoffSequence = sequence(run.action_cutoff_sequence);
    const reconciledActionSequence = sequence(run.reconciled_action_sequence);
    if (actionCutoffSequence === null || reconciledActionSequence === null || reconciledActionSequence < actionCutoffSequence) {
      fail(409, 'TASK_OBSERVATION_RECONCILIATION_PENDING', 'Admitted actions have not reached the immutable task cutoff');
    }
    if (!['training', 'ranked'].includes(run.mode) || run.task_ids[target.taskIndex] !== run.task_id) {
      fail(409, 'TASK_OBSERVATION_RUN_BINDING_MISMATCH', 'The task identity does not match its admitted run');
    }

    const closureRows = await tx.execute(sql`SELECT id,operation_id,payload_hash,reason,action_cutoff_sequence,owner_id,agent_id
      FROM oid_run_task_closure WHERE id=${run.closure_id} AND run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`) as unknown as ClosureRow[];
    const closure = closureRows[0];
    if (!closure || closure.owner_id !== run.owner_id || closure.agent_id !== run.agent_id ||
        sequence(closure.action_cutoff_sequence) !== actionCutoffSequence ||
        closure.operation_id !== run.closure_operation_id || closure.payload_hash !== run.closure_payload_hash || closure.reason !== run.closure_reason) {
      fail(409, 'TASK_OBSERVATION_CLOSURE_MISMATCH', 'The immutable closure does not match the task cutoff');
    }

    const preparationRows = await tx.execute(sql`SELECT i.preparation_id,i.lease_id,i.environment_id,i.release_identity,i.manifest_hash,
        i.task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.environment_manifest_sha256,i.application_source_hash,i.execution_identity_hash,
        l.state AS lease_state,o.status AS observation_status,o.generation_id,o.baseline_state_sha256
      FROM oid_task_preparation_intent i
      JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256 FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
      WHERE i.run_id=${target.runId} AND i.task_index=${target.taskIndex} FOR UPDATE OF i,l`) as unknown as PreparationRow[];
    const preparation = preparationRows[0];
    if (!preparation || !preparation.generation_id || preparation.baseline_state_sha256 !== preparation.initial_state_sha256) {
      fail(503, 'TASK_OBSERVATION_PREPARATION_UNAVAILABLE', 'The exact task preparation baseline is unavailable');
    }

    const bindingRows = await tx.execute(sql`SELECT env_id,generation_id,manifest_hash,application_source_hash
      FROM oid_task_execution_binding WHERE run_id=${target.runId} AND task_index=${target.taskIndex} FOR KEY SHARE`) as unknown as ExecutionBindingRow[];
    const executionBinding = bindingRows[0];
    if (!executionBinding || executionBinding.env_id !== preparation.environment_id || executionBinding.generation_id !== preparation.generation_id ||
        executionBinding.manifest_hash !== preparation.environment_manifest_sha256 ||
        executionBinding.application_source_hash !== preparation.application_source_hash ||
        preparation.release_identity !== run.release_identity || preparation.manifest_hash !== run.manifest_hash ||
        preparation.task_id !== run.task_id) {
      fail(409, 'TASK_OBSERVATION_EXECUTION_BINDING_MISMATCH', 'The run, prepared case, lease, and execution generation do not match');
    }

    const release = await deps.taskReleaseSource.getValidatedReleaseRecord(run.release_identity, run.manifest_hash, tx);
    if (!release || release.releaseIdentity !== run.release_identity || release.manifestHash !== run.manifest_hash ||
        release.manifest.releaseIdentity !== run.release_identity || release.manifest.manifestHash !== run.manifest_hash) {
      fail(503, 'TASK_OBSERVATION_RELEASE_UNAVAILABLE', 'The immutable admitted release cannot be verified');
    }
    const taskCase = release.manifest.cases[run.mode].find((entry) => entry.taskId === run.task_id);
    if (!taskCase || taskCase.caseId !== preparation.case_id || taskCase.caseHash !== preparation.case_hash ||
        taskCase.executionIdentityHash !== preparation.execution_identity_hash ||
        taskCase.initialState.stateSha256 !== preparation.initial_state_sha256) {
      fail(409, 'TASK_OBSERVATION_CASE_BINDING_MISMATCH', 'The preparation does not match the immutable admitted case');
    }

    const binding = expectedBinding(run, target.runId, preparation.environment_id, preparation.case_id, taskCase);
    const actionSequences = validateObservationPayload(observations, binding, frozenCandidate.observationCutoffSequence, actionCutoffSequence);
    if (actionSequences.length) {
      const actionRows = await tx.execute(sql`SELECT action_sequence FROM oid_run_task_action
        WHERE run_id=${target.runId} AND task_index=${target.taskIndex} AND action_sequence IN (
          SELECT value::bigint FROM jsonb_array_elements_text(${JSON.stringify(actionSequences)}::jsonb) AS requested(value)
        )`) as unknown as Array<{ action_sequence: string | number }>;
      const admittedSequences = new Set(actionRows.map((row) => sequence(row.action_sequence)).filter((value): value is number => value !== null));
      if (actionSequences.some((actionSequence) => !admittedSequences.has(actionSequence))) {
        fail(409, 'TASK_OBSERVATION_ACTION_BINDING_MISMATCH', 'An observation references an action sequence absent from the admitted task journal');
      }
    }
    const bundle: SealedTaskObservationBundle = {
      schemaVersion: 'bts-task-observation-bundle/v1',
      binding,
      closure: {
        closureId: closure.id,
        operationId: closure.operation_id,
        payloadHash: closure.payload_hash,
        reason: closure.reason,
        actionCutoffSequence,
        reconciledActionSequence,
      },
      execution: {
        preparationId: preparation.preparation_id,
        leaseId: preparation.lease_id,
        generationId: preparation.generation_id,
        environmentManifestHash: preparation.environment_manifest_sha256,
        applicationSourceHash: preparation.application_source_hash,
        executionIdentityHash: preparation.execution_identity_hash,
        initialStateSha256: preparation.initial_state_sha256,
      },
      cutoff: { observationSequence: frozenCandidate.observationCutoffSequence, status: 'authoritative', evidence: cutoffEvidence },
      observations,
    };
    assertJsonAndNoSecrets(bundle);
    const bundleHash = sha256CanonicalTaskJson(bundle);

    const priorRows = await tx.execute(sql`SELECT bundle_hash,bundle_json,created_at FROM oid_run_task_observation_bundle
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as StoredRow[];
    if (priorRows[0]) return storedRecord(priorRows[0], bundleHash);

    if (preparation.lease_state !== 'leased' || preparation.observation_status !== 'ready') {
      fail(409, 'TASK_OBSERVATION_LEASE_NOT_ACTIVE', 'A new observation bundle requires the exact prepared generation lease to remain leased');
    }

    await tx.execute(sql`INSERT INTO oid_run_task_observation_bundle(
        run_id,task_index,owner_id,agent_id,closure_id,closure_operation_id,closure_payload_hash,closure_reason,task_id,release_identity,release_manifest_hash,
        case_id,case_hash,rubric_hash,environment_id,preparation_id,lease_id,generation_id,environment_manifest_hash,
        application_source_hash,execution_identity_hash,initial_state_sha256,action_cutoff_sequence,reconciled_action_sequence,
        observation_cutoff_sequence,cutoff_evidence,bundle_hash,bundle_json
      ) VALUES (
        ${target.runId},${target.taskIndex},${binding.ownerId},${binding.agentId},${closure.id},${closure.operation_id},${closure.payload_hash},${closure.reason},
        ${binding.taskId},${binding.releaseIdentity},${binding.manifestHash},${binding.caseId},${binding.caseHash},${binding.rubricHash},
        ${binding.environmentId},${preparation.preparation_id},${preparation.lease_id},${preparation.generation_id},
        ${preparation.environment_manifest_sha256},${preparation.application_source_hash},${preparation.execution_identity_hash},
        ${preparation.initial_state_sha256},${actionCutoffSequence}::bigint,${reconciledActionSequence}::bigint,
        ${frozenCandidate.observationCutoffSequence}::bigint,${canonicalTaskJson(cutoffEvidence)}::jsonb,
        ${bundleHash},${canonicalTaskJson(bundle)}::jsonb
      )`);

    const storedRows = await tx.execute(sql`SELECT bundle_hash,bundle_json,created_at FROM oid_run_task_observation_bundle
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as StoredRow[];
    if (!storedRows[0]) throw new Error('The immutable task observation bundle could not be read back');
    const record = storedRecord(storedRows[0], bundleHash);
    return { ...record, replayed: false };
  });
}

/** Read and re-hash a retained internal bundle; this is not an owner-facing endpoint. */
export async function readSealedTaskObservationBundle(
  db: OwnerDatabase,
  target: { runId: string; taskIndex: number },
): Promise<Extract<TaskObservationStoreResult, { status: 'sealed' }> | null> {
  validateTarget(target.runId, target.taskIndex);
  return db.transaction(async (tx) => {
    await tx.execute(sql`SET TRANSACTION READ ONLY`);
    const rows = await tx.execute(sql`SELECT bundle_hash,bundle_json,created_at FROM oid_run_task_observation_bundle
      WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as unknown as StoredRow[];
    const row = rows[0];
    if (!row) return null;
    const result = storedRecord(row);
    return { ...result, replayed: false };
  });
}
