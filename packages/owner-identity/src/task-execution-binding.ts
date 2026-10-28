import { sql, type SQL } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { sha256CanonicalTaskJson } from './task-release.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;

/** Public identities only. Tokens, signatures and keys have no storage column. */
export interface PublicTaskExecutionBindingInput {
  runId: string; taskIndex: number; envId: string; generationId: string;
  manifestHash: string; applicationSourceHash: string; participantId?: string; payerAddress?: string;
}
export interface PublicTaskExecutionBinding {
  runId: string; taskIndex: number; envId: string; generationId: string;
  manifestHash: string; applicationSourceHash: string; participantId: string | null;
  payerAddress: string | null; createdAt: string;
}
export interface TaskExecutionBindingReader { execute(query: SQL): PromiseLike<unknown> }

export interface TaskExecutionContext {
  runId: string; taskIndex: number; taskId: string; mode: 'training' | 'ranked'; runStatus: string;
  selectedTaskIds: string[]; releaseIdentity: string; releaseManifestHash: string;
  preparationId: string; leaseId: string; claimId: string; envId: string; generationId: string;
  caseId: string; caseHash: string; initialStateSha256: string; executionIdentityHash: string;
  environmentManifestSha256: string; applicationSourceHash: string;
  participantId: string | null; payerAddress: string | null; environmentEvidenceHash: string;
  taskStatus: string; closureStatus: string; hasExecutionBinding: boolean;
}

type TaskExecutionContextRow = {
  run_id: string; run_status: string; mode: 'training' | 'ranked'; task_ids: string[];
  release_identity: string; run_manifest_hash: string; run_live: boolean;
  task_index: number; task_id: string; task_status: string; closure_status: string; task_live: boolean;
  active_task_count: number; preparation_id: string; lease_id: string; preparation_claim_id: string;
  preparation_environment_id: string; preparation_release_identity: string; preparation_manifest_hash: string;
  preparation_task_id: string; case_id: string; case_hash: string; initial_state_sha256: string;
  execution_identity_hash: string; environment_manifest_sha256: string; application_source_hash: string;
  lease_state: string; observation_status: string; observation_generation_id: string | null;
  baseline_state_sha256: string | null; fixture_evidence: unknown; baseline_evidence: unknown;
  observation_participant_id: string | null; observation_payer_address: string | null;
  registered_generation_id: string | null; generation_environment_id: string | null;
  binding_environment_id: string | null; binding_generation_id: string | null;
  binding_manifest_hash: string | null; binding_application_source_hash: string | null;
  binding_participant_id: string | null; binding_payer_address: string | null;
  run_claim_id: string | null; claim_status: string | null; slot_claim_id: string | null; slot_state: string | null;
};

/**
 * Read the exact task-scoped environment authority. The run's environment_id
 * is a compatibility pointer and is intentionally not consulted here.
 */
export async function getTaskExecutionContext(
  reader: TaskExecutionBindingReader,
  target: { runId: string; taskIndex: number },
  options: { requireActive?: boolean; requireBinding?: boolean } = {},
): Promise<TaskExecutionContext | null> {
  validateTarget(target);
  const requireActive = options.requireActive ?? true;
  const requireBinding = options.requireBinding ?? true;
  const found = await reader.execute(sql`SELECT r.id AS run_id,r.status AS run_status,r.mode,r.task_ids,r.release_identity,
      r.manifest_hash AS run_manifest_hash,r.overall_deadline>clock_timestamp() AS run_live,
      t.task_index,t.task_id,t.status AS task_status,t.closure_status,t.deadline_at>clock_timestamp() AS task_live,
      (SELECT count(*)::int FROM oid_run_task active WHERE active.run_id=r.id AND active.status='active') AS active_task_count,
      i.preparation_id,i.lease_id,i.claim_id AS preparation_claim_id,i.environment_id AS preparation_environment_id,
      i.release_identity AS preparation_release_identity,i.manifest_hash AS preparation_manifest_hash,
      i.task_id AS preparation_task_id,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
      i.environment_manifest_sha256,i.application_source_hash,l.state AS lease_state,
      o.status AS observation_status,o.generation_id AS observation_generation_id,o.baseline_state_sha256,
      o.fixture_evidence,o.baseline_evidence,o.participant_id AS observation_participant_id,o.payer_address AS observation_payer_address,
      g.generation_id AS registered_generation_id,g.environment_id AS generation_environment_id,
      eb.env_id AS binding_environment_id,eb.generation_id AS binding_generation_id,
      eb.manifest_hash AS binding_manifest_hash,eb.application_source_hash AS binding_application_source_hash,
      eb.participant_id AS binding_participant_id,eb.payer_address AS binding_payer_address,
      c.claim_id AS run_claim_id,c.status AS claim_status,s.claim_id AS slot_claim_id,s.state AS slot_state
    FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=${target.taskIndex}
    JOIN oid_task_preparation_intent i ON i.run_id=r.id AND i.task_index=t.task_index
    JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256,fixture_evidence,baseline_evidence,participant_id,payer_address
      FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
    JOIN oid_task_preparation_generation g ON g.preparation_id=i.preparation_id
    LEFT JOIN oid_task_execution_binding eb ON eb.run_id=r.id AND eb.task_index=t.task_index
    LEFT JOIN oid_run_dispatch_claim c ON c.run_id=r.id
    LEFT JOIN oid_run_execution_slot s ON s.run_id=r.id AND s.agent_id=r.agent_id AND s.released_at IS NULL
    WHERE r.id=${target.runId.toLowerCase()}`) as TaskExecutionContextRow[];
  if (!Array.isArray(found) || found.length !== 1) return null;
  const row = found[0]!;
  const hasBinding = row.binding_generation_id !== null;
  const participantId = hasBinding ? row.binding_participant_id : row.observation_participant_id;
  const payerAddress = (hasBinding ? row.binding_payer_address : row.observation_payer_address)?.toLowerCase() ?? null;
  const observedPayer = row.observation_payer_address?.toLowerCase() ?? null;
  if (row.run_id !== target.runId.toLowerCase() || row.task_index !== target.taskIndex ||
      row.task_ids[target.taskIndex] !== row.task_id || row.preparation_task_id !== row.task_id ||
      row.preparation_release_identity !== row.release_identity || row.preparation_manifest_hash !== row.run_manifest_hash ||
      row.preparation_claim_id !== row.run_claim_id || !row.case_id || !HASH.test(row.case_hash) ||
      !HASH.test(row.initial_state_sha256) || !HASH.test(row.execution_identity_hash) ||
      !HASH.test(row.environment_manifest_sha256) || !HASH.test(row.application_source_hash) ||
      !row.observation_generation_id || row.registered_generation_id !== row.observation_generation_id ||
      row.generation_environment_id !== row.preparation_environment_id ||
      row.baseline_state_sha256 !== row.initial_state_sha256 ||
      (hasBinding && (row.observation_participant_id !== (row.binding_participant_id ?? null) || observedPayer !== payerAddress)) ||
      (requireBinding && !hasBinding) ||
      (hasBinding && (row.binding_environment_id !== row.preparation_environment_id ||
        row.binding_generation_id !== row.observation_generation_id ||
        row.binding_manifest_hash !== row.environment_manifest_sha256 ||
        row.binding_application_source_hash !== row.application_source_hash))) return null;
  if (requireActive && (row.run_status !== 'running' || !row.run_live || row.task_status !== 'active' ||
      row.closure_status !== 'open' || !row.task_live || row.active_task_count !== 1 ||
      row.lease_state !== 'leased' || row.observation_status !== 'ready' ||
      row.claim_status !== 'claimed' || row.slot_state !== 'running' ||
      row.slot_claim_id !== row.run_claim_id)) return null;
  if (!requireActive && (!['leased', 'fenced'].includes(row.lease_state) ||
      !['ready', 'fenced'].includes(row.observation_status))) return null;
  const evidenceHash = sha256CanonicalTaskJson({
    preparationId: row.preparation_id, leaseId: row.lease_id, runId: row.run_id,
    taskIndex: row.task_index, claimId: row.preparation_claim_id,
    releaseIdentity: row.preparation_release_identity, manifestHash: row.preparation_manifest_hash,
    taskId: row.preparation_task_id, caseId: row.case_id, caseHash: row.case_hash,
    initialStateSha256: row.initial_state_sha256, executionIdentityHash: row.execution_identity_hash,
    environmentManifestSha256: row.environment_manifest_sha256, applicationSourceHash: row.application_source_hash,
    generationId: row.observation_generation_id, baselineStateSha256: row.baseline_state_sha256,
    fixtureEvidence: row.fixture_evidence, baselineEvidence: row.baseline_evidence,
  });
  return {
    runId: row.run_id, taskIndex: row.task_index, taskId: row.task_id, mode: row.mode, runStatus: row.run_status,
    selectedTaskIds: row.task_ids, releaseIdentity: row.release_identity, releaseManifestHash: row.run_manifest_hash,
    preparationId: row.preparation_id, leaseId: row.lease_id, claimId: row.preparation_claim_id,
    envId: row.preparation_environment_id, generationId: row.observation_generation_id,
    caseId: row.case_id, caseHash: row.case_hash, initialStateSha256: row.initial_state_sha256,
    executionIdentityHash: row.execution_identity_hash, environmentManifestSha256: row.environment_manifest_sha256,
    applicationSourceHash: row.application_source_hash, participantId,
    payerAddress, environmentEvidenceHash: evidenceHash,
    taskStatus: row.task_status, closureStatus: row.closure_status, hasExecutionBinding: hasBinding,
  };
}

function validateTarget(target: { runId: string; taskIndex: number }): void {
  if (!UUID.test(target.runId) || !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) {
    throw new HttpError(400, 'INVALID_EXECUTION_BINDING', 'A run UUID and bounded task index are required');
  }
}
function normalized(input: PublicTaskExecutionBindingInput): Omit<PublicTaskExecutionBinding, 'createdAt'> {
  validateTarget(input);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(input.envId) || !UUID.test(input.generationId) ||
      !HASH.test(input.manifestHash) || !HASH.test(input.applicationSourceHash) ||
      (input.participantId !== undefined && (!input.participantId.length || input.participantId.length > 160 || /[\u0000-\u001f]/.test(input.participantId))) ||
      (input.payerAddress !== undefined && !/^0x[0-9a-f]{40}$/i.test(input.payerAddress))) {
    throw new HttpError(400, 'INVALID_EXECUTION_BINDING', 'The public execution identity is invalid');
  }
  return { runId: input.runId.toLowerCase(), taskIndex: input.taskIndex, envId: input.envId,
    generationId: input.generationId.toLowerCase(), manifestHash: input.manifestHash.toLowerCase(),
    applicationSourceHash: input.applicationSourceHash.toLowerCase(), participantId: input.participantId ?? null,
    payerAddress: input.payerAddress?.toLowerCase() ?? null };
}

type BindingRow = {
  run_id: string; task_index: number; env_id: string; generation_id: string;
  manifest_hash: string; application_source_hash: string; participant_id: string | null;
  payer_address: string | null; created_at: Date | string;
};
export async function getTaskExecutionBinding(
  reader: TaskExecutionBindingReader, target: { runId: string; taskIndex: number },
): Promise<PublicTaskExecutionBinding | null> {
  validateTarget(target);
  const rows = await reader.execute(sql`SELECT run_id,task_index,env_id,generation_id,manifest_hash,application_source_hash,
      participant_id,payer_address,created_at FROM oid_task_execution_binding
    WHERE run_id=${target.runId} AND task_index=${target.taskIndex}`) as BindingRow[];
  const row = rows[0];
  return row ? { runId: row.run_id, taskIndex: row.task_index, envId: row.env_id, generationId: row.generation_id,
    manifestHash: row.manifest_hash, applicationSourceHash: row.application_source_hash,
    participantId: row.participant_id, payerAddress: row.payer_address, createdAt: new Date(row.created_at).toISOString() } : null;
}
function matches(actual: PublicTaskExecutionBinding, expected: Omit<PublicTaskExecutionBinding, 'createdAt'>): boolean {
  return Object.entries(expected).every(([key, value]) => actual[key as keyof PublicTaskExecutionBinding] === value);
}
function contextMatches(context: TaskExecutionContext, expected: Omit<PublicTaskExecutionBinding, 'createdAt'>): boolean {
  return context.runId === expected.runId && context.taskIndex === expected.taskIndex &&
    context.envId === expected.envId && context.generationId === expected.generationId &&
    context.environmentManifestSha256 === expected.manifestHash && context.applicationSourceHash === expected.applicationSourceHash &&
    context.participantId === expected.participantId && context.payerAddress === expected.payerAddress;
}
/** Call under the dispatch transaction's existing owner/agent/run locks. */
export async function assertTaskExecutionBinding(reader: TaskExecutionBindingReader, input: PublicTaskExecutionBindingInput) {
  const expected = normalized(input);
  const binding = await getTaskExecutionBinding(reader, expected);
  const context = await getTaskExecutionContext(reader, expected, { requireActive: true });
  if (!binding || !matches(binding, expected) || !context || !contextMatches(context, expected)) {
    throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The task execution generation cannot be replaced or reused');
  }
  return binding;
}

/**
 * Insert the public execution identity in a caller-owned transaction. The
 * caller must already hold the owner, agent, and run locks and must be
 * committing the matching first-task start in that same transaction.
 */
export async function insertTaskExecutionBindingInTransaction(
  tx: TaskExecutionBindingReader,
  input: PublicTaskExecutionBindingInput,
): Promise<{ binding: PublicTaskExecutionBinding; inserted: boolean }> {
  const expected = normalized(input);
  const context = await getTaskExecutionContext(tx, expected, { requireActive: true, requireBinding: false });
  if (!context || !contextMatches(context, expected)) {
    throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'A new binding requires the exact active task preparation and ready generation');
  }
  const insertedRows = await tx.execute(sql`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,
      manifest_hash,application_source_hash,participant_id,payer_address)
    VALUES (${expected.runId},${expected.taskIndex},${expected.envId},${expected.generationId},${expected.manifestHash},
      ${expected.applicationSourceHash},${expected.participantId},${expected.payerAddress})
    ON CONFLICT DO NOTHING RETURNING run_id`) as Array<{ run_id: string }>;
  const binding = await getTaskExecutionBinding(tx, expected);
  if (!binding) {
    throw new HttpError(409, 'TASK_EXECUTION_GENERATION_IN_USE', 'The prepared generation is already bound to another task');
  }
  if (!matches(binding, expected)) {
    throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The persisted task generation does not match the prepared identity');
  }
  return { binding, inserted: insertedRows.length === 1 };
}

/**
 * AICODE-NOTE: RAM sessions disappear on restart; this immutable public pin
 * prevents a fresh generation from erasing a task's effects. Reading it never
 * reconstructs a bearer token or sends an action.
 */
export async function ensureTaskExecutionBinding(db: OwnerDatabase, input: PublicTaskExecutionBindingInput) {
  const expected = normalized(input);
  const targets = await db.execute(sql`SELECT owner_id,agent_id FROM oid_benchmark_run WHERE id=${expected.runId}`) as unknown as Array<{ owner_id: string; agent_id: string }>;
  if (!targets[0]) throw new HttpError(404, 'RUN_NOT_FOUND', 'The execution run does not exist');
  const target = targets[0];
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${target.owner_id} FOR NO KEY UPDATE`);
    await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${target.agent_id} AND owner_id=${target.owner_id} FOR NO KEY UPDATE`);
    const runs = await tx.execute(sql`SELECT status,task_ids,overall_deadline>clock_timestamp() AS live
      FROM oid_benchmark_run WHERE id=${expected.runId} AND owner_id=${target.owner_id} AND agent_id=${target.agent_id} FOR UPDATE`) as unknown as Array<{
        status: string; task_ids: string[]; live: boolean;
      }>;
    const run = runs[0];
    if (!run || run.status !== 'running') throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The binding must belong to a running execution');
    const prior = await getTaskExecutionBinding(tx, expected);
    if (prior) {
      const context = await getTaskExecutionContext(tx, expected, { requireActive: false });
      if (!matches(prior, expected) || !context || !contextMatches(context, expected)) {
        throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The persisted task generation is not bound to its exact preparation');
      }
      return { binding: prior, replayed: true };
    }
    const tasks = await tx.execute(sql`SELECT task_id,status,closure_status,deadline_at>clock_timestamp() AS live FROM oid_run_task
      WHERE run_id=${expected.runId} AND task_index=${expected.taskIndex} FOR UPDATE`) as unknown as Array<{
        task_id: string; status: string; closure_status: string; live: boolean;
      }>;
    if (!run.live || tasks[0]?.status !== 'active' || run.task_ids[expected.taskIndex] !== tasks[0].task_id ||
        tasks[0].closure_status !== 'open' || !tasks[0].live) {
      throw new HttpError(409, 'TASK_EXECUTION_BINDING_CLOSED', 'A new binding requires an active open task within its original deadlines');
    }
    const context = await getTaskExecutionContext(tx, expected, { requireActive: true, requireBinding: false });
    if (!context || !contextMatches(context, expected)) {
      throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'The binding must match the active task preparation and ready generation');
    }
    await tx.execute(sql`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,
        application_source_hash,participant_id,payer_address)
      VALUES (${expected.runId},${expected.taskIndex},${expected.envId},${expected.generationId},${expected.manifestHash},
        ${expected.applicationSourceHash},${expected.participantId},${expected.payerAddress}) ON CONFLICT DO NOTHING`);
    const binding = await getTaskExecutionBinding(tx, expected);
    if (!binding) throw new HttpError(409, 'TASK_EXECUTION_GENERATION_IN_USE', 'This generation is already bound to another task');
    if (!matches(binding, expected)) throw new HttpError(409, 'TASK_EXECUTION_BINDING_MISMATCH', 'Concurrent binding changed the task identity');
    return { binding, replayed: false };
  });
}
