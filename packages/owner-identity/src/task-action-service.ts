import { createHash, randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { AgentPrincipal } from './agents.js';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { canonicalTaskJson } from './task-release.js';
import { assertTaskPaymentProtocol, resolveTaskPaymentReference } from './task-payment-references.js';
import { getTaskExecutionContext } from './task-execution-binding.js';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const operationIdPattern = /^[A-Za-z0-9_-]{12,128}$/;
const uint = z.string().regex(/^(?:0|[1-9][0-9]{0,77})$/);
const address = z.string().regex(/^0x[0-9a-f]{40}$/i).transform((value) => value.toLowerCase());
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);

/**
 * Bounded action vocabulary mirrored from the deployed BEF participant tools.
 * Commands contain no URL, RPC method, transaction calldata, payment signature,
 * bearer credential, or administrative operation. Environment hard limits and
 * execution remain owned by the selected executor.
 */
export const TaskActionCommandSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('inspect_catalog') }).strict(),
  z.object({ kind: z.literal('inspect_offer'), resourceId: identifier, offerId: identifier.optional() }).strict(),
  z.object({ kind: z.literal('purchase'), resourceId: identifier, offerId: identifier }).strict(),
  z.object({ kind: z.literal('pay'), resourceId: identifier, offerId: identifier, offerReadActionId: z.string().uuid() }).strict(),
  z.object({ kind: z.literal('retrieve'), payActionId: z.string().uuid() }).strict(),
  z.object({ kind: z.literal('approve'), tokenAssetId: z.enum(['WETH', 'USDC']).default('WETH'), amountUnits: uint, gasLimit: uint }).strict(),
  z.object({ kind: z.literal('transfer'), amountUnits: uint, recipient: address, gasLimit: uint }).strict(),
  z.object({ kind: z.literal('wrap'), amountWei: uint, gasLimit: uint }).strict(),
  z.object({ kind: z.literal('unwrap'), amountWei: uint, gasLimit: uint }).strict(),
  z.object({
    kind: z.literal('swap'), inputAssetId: z.enum(['WETH', 'USDC']), outputAssetId: z.enum(['WETH', 'USDC']),
    feeTier: z.union([z.literal(500), z.literal(3000)]).optional(),
    amountInUnits: uint, amountOutMinimumUnits: uint, recipient: address, gasLimit: uint,
  }).strict().refine((value) => value.inputAssetId !== value.outputAssetId, 'swap assets must differ'),
]);

// AICODE-NOTE: PostgreSQL JSONB cannot store NUL; reject before cutoff writes.
const shortAnswerString = z.string().max(512).regex(/^[^\u0000]*$/);
const S2TaskAnswerSchema = z.object({
  amountUnits: shortAnswerString.optional(), network: shortAnswerString.optional(), assetId: shortAnswerString.optional(),
  recipient: shortAnswerString.optional(), scheme: shortAnswerString.optional(), resourceId: shortAnswerString.optional(),
  offerId: shortAnswerString.optional(), version: shortAnswerString.optional(),
  authFields: z.array(z.object({ name: z.string().min(1).max(128).regex(/^[^\u0000]*$/), value: shortAnswerString }).strict()).max(128).optional(),
}).strict();
const S3TaskAnswerSchema = z.object({ offerId: z.string().max(128).regex(/^[^\u0000]*$/).optional() }).strict();
export const TaskFinishAnswerSchemas = { S2: S2TaskAnswerSchema, S3: S3TaskAnswerSchema } as const;
export type TaskFinishAnswer = z.infer<typeof S2TaskAnswerSchema> | z.infer<typeof S3TaskAnswerSchema>;

export type TaskActionCommand = z.infer<typeof TaskActionCommandSchema>;
type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
type SqlResult<T> = T[];

export interface TaskActionDependencies { db: OwnerDatabase }

/** Scoped command status is an observation projection, never a caller-supplied grade. */
export async function getTaskActionState(
  deps: TaskActionDependencies, principal: AgentPrincipal, target: { runId: string; actionId: string },
) {
  if (!uuidPattern.test(target.runId) || !uuidPattern.test(target.actionId)) throw new HttpError(400, 'INVALID_TASK_TARGET', 'Run and action UUIDs are required');
  return deps.db.transaction(async (tx) => {
    await lockOwner(tx, principal.ownerId);
    await lockAgentAndAuthorize(tx, principal);
    const run = await lockRun(tx, principal, target.runId);
    await currentModeAllowed(tx, principal, run);
    const found = await query<{
      id: string; task_index: number; task_id: string; action_sequence: string; receipt_status: string;
      receipt_revision: number; evidence_hash: string | null; transaction_hash: string | null;
      evidence_path: string | null; tool_response_json: unknown; tool_response_hash: string | null;
    }>(tx, sql`SELECT a.id,a.task_index,a.task_id,a.action_sequence::text,r.receipt_status,r.receipt_revision,r.evidence_hash,
        r.evidence_path,r.transaction_hash,r.tool_response_json,r.tool_response_hash
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.id=${target.actionId} AND a.run_id=${target.runId} AND a.owner_id=${principal.ownerId} AND a.agent_id=${principal.agentId}`);
    const action = found[0];
    if (!action) throw new HttpError(404, 'TASK_ACTION_NOT_FOUND', 'The action does not exist for this run');
    const toolResponse = typeof action.tool_response_json === 'string' ? JSON.parse(action.tool_response_json) : action.tool_response_json;
    if (toolResponse !== null && toolResponse !== undefined && hash(toolResponse) !== action.tool_response_hash) throw new Error('Task tool response hash mismatch');
    return { actionId: action.id, runId: target.runId, taskIndex: action.task_index, taskId: action.task_id,
      actionSequence: action.action_sequence, status: action.receipt_status, receiptRevision: action.receipt_revision,
      evidenceHash: action.evidence_hash, evidencePath: action.evidence_path,
      transactionHash: action.transaction_hash, toolResponse: toolResponse ?? null };
  });
}

export interface AdmitTaskActionInput {
  runId: string;
  taskIndex: number;
  operationId: string;
  command: unknown;
}

export interface TaskActionAdmission {
  admitted: true;
  actionId: string;
  runId: string;
  taskIndex: number;
  taskId: string;
  actionSequence: string;
  acceptedAt: string;
  replayed: boolean;
}

export interface TaskActionCutoffResult {
  admitted: false;
  reason: 'task_deadline' | 'run_deadline';
  closureId: string;
  actionCutoffSequence: string;
  closureStatus: 'closing' | 'closed' | 'unknown';
}

export interface FinishTaskInput { runId: string; taskIndex: number; operationId: string; answer?: unknown }

export interface FinishTaskResult {
  closureId: string;
  runId: string;
  taskIndex: number;
  taskId: string;
  reason: 'agent_finish' | 'task_deadline' | 'run_deadline';
  actionCutoffSequence: string;
  reconciledActionSequence: string;
  closureStatus: 'closing' | 'closed' | 'unknown';
  closedAt: string | null;
  replayed: boolean;
}

export interface TaskActionReceiptInput {
  actionId: string;
  status: 'observed' | 'rejected_before_execution' | 'unknown';
  evidenceHash: string;
  /** Trusted repo-relative evidence artifact path; null on legacy hash-only rows. */
  evidencePath?: string;
  transactionHash?: string;
  /** Sanitized normal participant tool response from the trusted execution adapter. */
  toolResponse?: Record<string, unknown>;
}

export interface TaskActionReceiptResult {
  actionId: string;
  actionSequence: string;
  receiptRevision: number;
  receiptStatus: 'observed' | 'rejected_before_execution' | 'unknown';
  reconciledActionSequence: string;
  closureStatus: 'open' | 'closing' | 'closed' | 'unknown';
  replayed: boolean;
}

interface RunRow {
  id: string; owner_id: string; agent_id: string; access_generation: number; agent_policy_revision: number;
  mode: 'training' | 'ranked'; task_ids: string[]; status: string; overall_deadline: Date | string | null; environment_id: string | null;
}

interface TaskRow {
  run_id: string; task_index: number; task_id: string; status: string; started_at: Date | string | null;
  deadline_at: Date | string | null; accepted_action_sequence: string | number; action_cutoff_sequence: string | number | null;
  reconciled_action_sequence: string | number; closure_status: 'open' | 'closing' | 'closed' | 'unknown'; closure_id: string | null;
  closure_operation_id: string | null; closure_payload_hash: string | null;
  closure_reason: 'agent_finish' | 'task_deadline' | 'run_deadline' | null; closed_at: Date | string | null;
}

interface ActionRow {
  id: string; run_id: string; task_index: number; task_id: string; action_sequence: string | number;
  operation_id: string; payload_hash: string; accepted_at: Date | string;
}

interface ClosureRow {
  id: string; run_id: string; task_index: number; operation_id: string | null; payload_hash: string;
  reason: 'agent_finish' | 'task_deadline' | 'run_deadline'; action_cutoff_sequence: string | number;
  requested_at: Date | string;
}

function rows<T>(value: unknown): SqlResult<T> {
  if (!Array.isArray(value)) throw new Error('The PostgreSQL driver returned an unexpected task action result');
  return value as SqlResult<T>;
}

async function query<T>(tx: Transaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

function iso(value: Date | string | null): string | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error('PostgreSQL returned an invalid task action timestamp');
  return date.toISOString();
}

function validTarget(runId: string, taskIndex: number): void {
  if (!uuidPattern.test(runId) || !Number.isSafeInteger(taskIndex) || taskIndex < 0 || taskIndex > 11) {
    throw new HttpError(400, 'INVALID_TASK_TARGET', 'A run UUID and bounded task index are required');
  }
}

function validOperationId(operationId: string): void {
  if (!operationIdPattern.test(operationId)) throw new HttpError(400, 'INVALID_OPERATION_ID', 'operationId must be a 12-128 character idempotency key');
}

function parseCommand(value: unknown): TaskActionCommand {
  const parsed = TaskActionCommandSchema.safeParse(value);
  if (!parsed.success) throw new HttpError(400, 'INVALID_TASK_ACTION', 'The task action is outside the supported participant tool schema');
  return parsed.data;
}

/** Validate optional answer data before any finish/cutoff state transition. */
export function parseTaskFinishAnswer(taskId: string, value: unknown): TaskFinishAnswer | undefined {
  if (value === undefined) return undefined;
  const schema = taskId === 'S2' ? S2TaskAnswerSchema : taskId === 'S3' ? S3TaskAnswerSchema : null;
  if (!schema) throw new HttpError(400, 'INVALID_TASK_ANSWER', 'This task does not accept a structured finish answer');
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    // AICODE-NOTE: Disclose schema paths, never rejected values or unknown key names.
    const allowed = new Set(['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version', 'authFields', 'name', 'value']);
    const paths = [...new Set(parsed.error.issues.slice(0, 4).map((issue) => {
      const path = issue.path.filter((part) => typeof part === 'number' || (typeof part === 'string' && allowed.has(part)));
      return 'answer' + path.map((part) => typeof part === 'number' ? `[${part}]` : `.${String(part)}`).join('');
    }))];
    throw new HttpError(400, 'INVALID_TASK_ANSWER', `The structured task answer is malformed at ${paths.join(', ')}; follow current_task.task.answerContract.schema`);
  }
  return parsed.data;
}

function hash(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}

function date(value: Date | string | null): Date | null {
  if (value === null) return null;
  const result = value instanceof Date ? value : new Date(value);
  return Number.isFinite(result.getTime()) ? result : null;
}

async function lockOwner(tx: Transaction, ownerId: string): Promise<void> {
  const found = await query<{ id: string }>(tx, sql`SELECT id FROM oid_owner WHERE id=${ownerId} FOR NO KEY UPDATE`);
  if (!found.length) throw new HttpError(403, 'AGENT_ACCESS_REVOKED', 'Current agent access is required');
}

async function lockAgentAndAuthorize(tx: Transaction, principal: AgentPrincipal): Promise<{ accessGeneration: number }> {
  if (principal.role !== 'agent' || principal.accessGeneration < 1 || !principal.grantId || !principal.resource) {
    throw new HttpError(401, 'UNAUTHORIZED', 'A verified scoped agent grant is required');
  }
  const agents = await query<{
    id: string; access_generation: number; access_revoked_at: unknown; admission_status: string; training: boolean; ranked: boolean;
  }>(tx, sql`SELECT a.id,a.access_generation,a.access_revoked_at,o.admission_status,p.training,p.ranked
      FROM oid_agent a JOIN oid_owner o ON o.id=a.owner_id JOIN oid_agent_policy p ON p.agent_id=a.id
      WHERE a.id=${principal.agentId} AND a.owner_id=${principal.ownerId} FOR NO KEY UPDATE OF a`);
  const agent = agents[0];
  if (!agent || agent.access_revoked_at || agent.access_generation !== principal.accessGeneration || agent.admission_status !== 'admitted') {
    throw new HttpError(403, 'AGENT_ACCESS_REVOKED', 'Current agent access is required');
  }
  const grants = await query<{ id: string }>(tx, sql`SELECT id FROM oid_agent_access_grant
      WHERE id=${principal.grantId} AND owner_id=${principal.ownerId} AND agent_id=${principal.agentId}
        AND resource=${principal.resource} AND role='agent' AND access_generation=${agent.access_generation}
        AND revoked_at IS NULL AND expires_at>clock_timestamp()`);
  if (!grants.length) throw new HttpError(403, 'AGENT_ACCESS_REVOKED', 'The exact agent grant is no longer valid');
  return { accessGeneration: agent.access_generation };
}

async function lockRun(tx: Transaction, principal: AgentPrincipal, runId: string): Promise<RunRow> {
  const found = await query<RunRow>(tx, sql`SELECT * FROM oid_benchmark_run
    WHERE id=${runId} AND owner_id=${principal.ownerId} AND agent_id=${principal.agentId}
      AND access_generation=${principal.accessGeneration} FOR UPDATE`);
  const run = found[0];
  if (!run) throw new HttpError(404, 'RUN_NOT_FOUND', 'The run does not exist for this agent');
  return run;
}

async function currentModeAllowed(tx: Transaction, principal: AgentPrincipal, run: RunRow): Promise<void> {
  const modeRows = await query<{ training: boolean; ranked: boolean }>(tx, sql`SELECT training,ranked FROM oid_agent_policy WHERE agent_id=${principal.agentId}`);
  const policy = modeRows[0];
  if (!policy || !(run.mode === 'training' ? policy.training : policy.ranked)) {
    throw new HttpError(403, 'MODE_NOT_ALLOWED', 'Current permission for this run mode is required');
  }
  const fences = await query<{ fenced: boolean }>(tx, sql`SELECT EXISTS(
    SELECT 1 FROM oid_run_mode_cancellation_outbox WHERE owner_id=${principal.ownerId} AND agent_id=${principal.agentId}
      AND mode=${run.mode} AND policy_revision>${run.agent_policy_revision}
  ) AS fenced`);
  if (fences[0]?.fenced) throw new HttpError(403, 'RUN_MODE_FENCED', 'This run mode has been fenced by an owner policy change');
}

async function assertRunNotInPlatformRecovery(tx: Transaction, runId: string): Promise<void> {
  const rows = await query<{ recovering: boolean }>(tx, sql`SELECT EXISTS(
    SELECT 1 FROM oid_run_platform_recovery
    WHERE run_id=${runId} AND status IN ('recovering','unknown','exhausted')) AS recovering`);
  if (rows[0]?.recovering) {
    throw new HttpError(503, 'PLATFORM_RECOVERY_IN_PROGRESS', 'The task is paused while its original platform operation is being reconciled');
  }
}

async function databaseNow(tx: Transaction): Promise<Date> {
  const values = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
  const now = date(values[0]?.now ?? null);
  if (!now) throw new Error('PostgreSQL clock did not return a valid timestamp');
  return now;
}

async function appendRunEvent(
  tx: Transaction,
  runId: string,
  source: 'agent' | 'coordinator' | 'executor',
  eventType: string,
  payload: Record<string, unknown>,
): Promise<void> {
  const sequence = await query<{ next_sequence: number }>(tx, sql`SELECT COALESCE(MAX(sequence),0)+1 AS next_sequence
    FROM oid_run_event WHERE run_id=${runId}`);
  const payloadJson = canonicalTaskJson(payload);
  await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
    VALUES (${randomUUID()},${runId},${sequence[0]?.next_sequence ?? 1},${source},${eventType},${hash(payload)},${payloadJson}::jsonb)`);
}

async function cutoffState(tx: Transaction, task: TaskRow, now: Date): Promise<{
  cursor: bigint; status: 'open' | 'closing' | 'closed' | 'unknown'; closedAt: Date | null;
}> {
  const actions = await query<{ action_sequence: string | number; receipt_status: string | null }>(tx, sql`
    SELECT a.action_sequence::text AS action_sequence,r.receipt_status
      FROM oid_run_task_action a LEFT JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.run_id=${task.run_id} AND a.task_index=${task.task_index}
      ORDER BY a.action_sequence`);
  let cursor = 0n;
  let hasUnknown = false;
  for (const action of actions) {
    const sequence = BigInt(action.action_sequence);
    if (sequence !== cursor + 1n || !action.receipt_status || action.receipt_status === 'pending') break;
    cursor = sequence;
    if (action.receipt_status === 'unknown') hasUnknown = true;
  }
  const cutoff = task.action_cutoff_sequence === null ? null : BigInt(task.action_cutoff_sequence);
  const accepted = BigInt(task.accepted_action_sequence);
  if (cursor > accepted) throw new Error('Task action reconciliation cursor exceeds admitted actions');
  let status = task.closure_status;
  let closedAt = date(task.closed_at);
  if (cutoff !== null) {
    if (cursor >= cutoff) {
      status = hasUnknown ? 'unknown' : 'closed';
      if (!closedAt) closedAt = now;
    } else {
      status = 'closing';
      closedAt = null;
    }
  }
  return { cursor, status, closedAt };
}

async function persistCutoffProgress(tx: Transaction, task: TaskRow, now: Date): Promise<TaskRow> {
  const progress = await cutoffState(tx, task, now);
  const closedAt = progress.closedAt?.toISOString() ?? null;
  const updated = await query<TaskRow>(tx, sql`UPDATE oid_run_task SET
      reconciled_action_sequence=${progress.cursor.toString()},closure_status=${progress.status},closed_at=${closedAt}
    WHERE run_id=${task.run_id} AND task_index=${task.task_index}
    RETURNING run_id,task_index,task_id,status,started_at,deadline_at,accepted_action_sequence::text AS accepted_action_sequence,
      action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
      closure_status,closure_id,closure_operation_id,closure_payload_hash,closure_reason,closed_at`);
  if (!updated[0]) throw new Error('Task action progress update affected no task');
  return updated[0];
}

async function establishCutoff(
  tx: Transaction,
  run: RunRow,
  task: TaskRow,
  input: { reason: 'agent_finish' | 'task_deadline' | 'run_deadline'; operationId?: string; payloadHash: string;
    actor: 'agent' | 'coordinator'; principal?: AgentPrincipal; answer?: TaskFinishAnswer },
  now: Date,
): Promise<TaskRow> {
  if (task.closure_id) return task;
  const closureId = randomUUID();
  const cutoff = BigInt(task.accepted_action_sequence);
  const actorAgent = input.principal?.agentId ?? run.agent_id;
  await tx.execute(sql`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,answer_json,action_cutoff_sequence,
      actor_kind,owner_id,agent_id,access_generation,grant_id,requested_at)
    VALUES (${closureId},${run.id},${task.task_index},${input.operationId ?? null},${input.payloadHash},${input.reason},
      ${input.answer === undefined ? null : canonicalTaskJson(input.answer)}::jsonb,${cutoff.toString()},${input.actor},${run.owner_id},${actorAgent},
      ${input.principal?.accessGeneration ?? null},${input.principal?.grantId ?? null},${now.toISOString()})`);
  await tx.execute(sql`INSERT INTO oid_run_task_finish_outbox(closure_id,status,created_at) VALUES (${closureId},'pending',${now.toISOString()})`);
  const updated = await query<TaskRow>(tx, sql`UPDATE oid_run_task SET action_cutoff_sequence=${cutoff.toString()},closure_status='closing',
      closure_id=${closureId},closure_operation_id=${input.operationId ?? null},closure_payload_hash=${input.payloadHash},
      closure_reason=${input.reason},closed_at=NULL
    WHERE run_id=${task.run_id} AND task_index=${task.task_index} AND closure_id IS NULL
    RETURNING run_id,task_index,task_id,status,started_at,deadline_at,accepted_action_sequence::text AS accepted_action_sequence,
      action_cutoff_sequence::text AS action_cutoff_sequence,reconciled_action_sequence::text AS reconciled_action_sequence,
      closure_status,closure_id,closure_operation_id,closure_payload_hash,closure_reason,closed_at`);
  if (!updated[0]) throw new HttpError(409, 'TASK_CUTOFF_CONFLICT', 'A task cutoff was committed concurrently');
  await appendRunEvent(tx, run.id, input.actor, 'task.cutoff.established', {
    closureId, taskIndex: task.task_index, taskId: task.task_id, reason: input.reason, actionCutoffSequence: cutoff.toString(),
  });
  return persistCutoffProgress(tx, updated[0], now);
}

function finishView(task: TaskRow, replayed: boolean): FinishTaskResult {
  if (!task.closure_id || task.action_cutoff_sequence === null || !task.closure_reason) throw new Error('Task cutoff is incomplete');
  return {
    closureId: task.closure_id, runId: task.run_id, taskIndex: task.task_index, taskId: task.task_id,
    reason: task.closure_reason, actionCutoffSequence: String(task.action_cutoff_sequence),
    reconciledActionSequence: String(task.reconciled_action_sequence), closureStatus: task.closure_status as FinishTaskResult['closureStatus'],
    closedAt: iso(task.closed_at), replayed,
  };
}

/**
 * Persist one bounded participant-tool command for the current active task.
 * This commits an intent and internal outbox row only; it does not claim that
 * a transaction, payment, or external tool effect has occurred.
 */
export async function admitTaskAction(
  deps: TaskActionDependencies,
  principal: AgentPrincipal,
  input: AdmitTaskActionInput,
): Promise<TaskActionAdmission | TaskActionCutoffResult> {
  validTarget(input.runId, input.taskIndex);
  validOperationId(input.operationId);
  const command = parseCommand(input.command);
  const payloadHash = hash({ runId: input.runId, taskIndex: input.taskIndex, command });
  const result = await deps.db.transaction(async (tx) => {
    await lockOwner(tx, principal.ownerId);
    await lockAgentAndAuthorize(tx, principal);
    const run = await lockRun(tx, principal, input.runId);
    await currentModeAllowed(tx, principal, run);

    const prior = await query<ActionRow>(tx, sql`SELECT id,run_id,task_index,task_id,action_sequence::text AS action_sequence,
        operation_id,payload_hash,accepted_at
      FROM oid_run_task_action WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
    if (prior[0]) {
      const row = prior[0];
      if (row.task_index !== input.taskIndex || row.payload_hash !== payloadHash) {
        throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'operationId was already used for a different task action');
      }
      return { kind: 'admitted' as const, row, replayed: true };
    }
    await assertRunNotInPlatformRecovery(tx, run.id);
    const unresolved = await query<{ exists: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.run_id=${run.id} AND a.task_index=${input.taskIndex} AND r.receipt_status='unknown'
    ) AS exists`);
    if (unresolved[0]?.exists) throw new HttpError(409, 'TASK_RECONCILIATION_REQUIRED', 'An admitted action has unknown effects; reconcile its original identity before submitting another command');
    const priorClosure = await query<{ task_index: number }>(tx, sql`SELECT task_index FROM oid_run_task_closure
      WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
    if (priorClosure.length) throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'operationId already identifies a task closure');

    const taskRows = await query<TaskRow>(tx, sql`SELECT run_id,task_index,task_id,status,started_at,deadline_at,
        accepted_action_sequence::text AS accepted_action_sequence,action_cutoff_sequence::text AS action_cutoff_sequence,
        reconciled_action_sequence::text AS reconciled_action_sequence,closure_status,closure_id,closure_operation_id,
        closure_payload_hash,closure_reason,closed_at
      FROM oid_run_task WHERE run_id=${run.id} AND task_index=${input.taskIndex} FOR UPDATE`);
    const task = taskRows[0];
    if (!task || run.task_ids[input.taskIndex] !== task.task_id) throw new HttpError(404, 'TASK_NOT_FOUND', 'The task does not exist in this run');
    if (task.closure_id || task.closure_status !== 'open') throw new HttpError(409, 'TASK_CLOSED', 'The task no longer accepts actions');
    if (run.status !== 'running' || task.status !== 'active') throw new HttpError(409, 'TASK_NOT_ACTIVE', 'Only the current active task accepts actions');
    const active = await query<{ task_index: number }>(tx, sql`SELECT task_index FROM oid_run_task WHERE run_id=${run.id} AND status='active' FOR UPDATE`);
    if (active.length !== 1 || active[0]!.task_index !== input.taskIndex) throw new HttpError(409, 'TASK_NOT_ACTIVE', 'Only the current active task accepts actions');
    const now = await databaseNow(tx);
    const runDeadline = date(run.overall_deadline);
    const taskDeadline = date(task.deadline_at);
    if (!runDeadline || !taskDeadline) throw new HttpError(503, 'TASK_DEADLINE_UNAVAILABLE', 'The active task deadline is unavailable');
    if (now.getTime() >= runDeadline.getTime() || now.getTime() >= taskDeadline.getTime()) {
      const reason: TaskActionCutoffResult['reason'] = now.getTime() >= runDeadline.getTime() ? 'run_deadline' : 'task_deadline';
      const closed = await establishCutoff(tx, run, task, {
        reason, payloadHash: hash({ runId: run.id, taskIndex: task.task_index, reason }), actor: 'coordinator',
      }, now);
      return { kind: 'deadline' as const, task: closed, reason };
    }

    const execution = await getTaskExecutionContext(tx, { runId: run.id, taskIndex: task.task_index }, { requireActive: true });
    if (!execution || execution.taskId !== task.task_id || execution.runStatus !== 'running') {
      throw new HttpError(503, 'TASK_EXECUTION_IDENTITY_UNAVAILABLE', 'The exact active task preparation and execution binding are unavailable');
    }
    await assertTaskPaymentProtocol(tx, run.id, command);
    if (command.kind === 'pay' || command.kind === 'retrieve') {
      await resolveTaskPaymentReference(tx, { runId: run.id, taskIndex: task.task_index,
        environmentId: execution.envId, command });
    }
    const next = await query<{ action_sequence: string }>(tx, sql`UPDATE oid_run_task SET accepted_action_sequence=accepted_action_sequence+1
      WHERE run_id=${run.id} AND task_index=${task.task_index} AND closure_status='open' AND action_cutoff_sequence IS NULL
      RETURNING accepted_action_sequence::text AS action_sequence`);
    if (!next[0]) throw new HttpError(409, 'TASK_CLOSED', 'The task no longer accepts actions');
    const actionId = randomUUID();
    const acceptedAt = now.toISOString();
    await tx.execute(sql`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,
        task_id,environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json,accepted_at)
      VALUES (${actionId},${run.id},${task.task_index},${run.owner_id},${run.agent_id},${principal.accessGeneration},${principal.grantId},
        ${task.task_id},${execution.envId},
        ${next[0].action_sequence},${input.operationId},${payloadHash},${command.kind},${canonicalTaskJson(command)}::jsonb,${acceptedAt})`);
    await tx.execute(sql`INSERT INTO oid_run_task_action_outbox(action_id,status,created_at) VALUES (${actionId},'pending',${acceptedAt})`);
    await tx.execute(sql`INSERT INTO oid_run_task_action_receipt(action_id,receipt_status,updated_at) VALUES (${actionId},'pending',${acceptedAt})`);
    await appendRunEvent(tx, run.id, 'agent', 'task.action.admitted', {
      actionId, taskIndex: task.task_index, taskId: task.task_id, actionSequence: next[0].action_sequence,
      operationId: input.operationId, actionKind: command.kind, payloadHash,
    });
    const row: ActionRow = {
      id: actionId, run_id: run.id, task_index: task.task_index, task_id: task.task_id,
      action_sequence: next[0].action_sequence, operation_id: input.operationId, payload_hash: payloadHash, accepted_at: acceptedAt,
    };
    return { kind: 'admitted' as const, row, replayed: false };
  });

  if (result.kind === 'deadline') return {
    admitted: false, reason: result.reason, closureId: result.task.closure_id!,
    actionCutoffSequence: String(result.task.action_cutoff_sequence), closureStatus: result.task.closure_status as TaskActionCutoffResult['closureStatus'],
  };
  return {
    admitted: true, actionId: result.row.id, runId: result.row.run_id, taskIndex: result.row.task_index,
    taskId: result.row.task_id, actionSequence: String(result.row.action_sequence), acceptedAt: iso(result.row.accepted_at)!, replayed: result.replayed,
  };
}

/** Explicit finish has no score field and commits only the shared task cutoff. */
export async function finishTask(
  deps: TaskActionDependencies,
  principal: AgentPrincipal,
  input: FinishTaskInput,
): Promise<FinishTaskResult> {
  validTarget(input.runId, input.taskIndex);
  validOperationId(input.operationId);
  return deps.db.transaction(async (tx) => {
    await lockOwner(tx, principal.ownerId);
    await lockAgentAndAuthorize(tx, principal);
    const run = await lockRun(tx, principal, input.runId);
    await currentModeAllowed(tx, principal, run);
    const taskRows = await query<TaskRow>(tx, sql`SELECT run_id,task_index,task_id,status,started_at,deadline_at,
        accepted_action_sequence::text AS accepted_action_sequence,action_cutoff_sequence::text AS action_cutoff_sequence,
        reconciled_action_sequence::text AS reconciled_action_sequence,closure_status,closure_id,closure_operation_id,
        closure_payload_hash,closure_reason,closed_at
      FROM oid_run_task WHERE run_id=${run.id} AND task_index=${input.taskIndex} FOR UPDATE`);
    let task = taskRows[0];
    if (!task || run.task_ids[input.taskIndex] !== task.task_id) throw new HttpError(404, 'TASK_NOT_FOUND', 'The task does not exist in this run');
    const answer = parseTaskFinishAnswer(task.task_id, input.answer);
    const payloadHash = hash({ action: 'task_finish', runId: run.id, taskIndex: task.task_index, answer: answer ?? null });
    if (task.closure_id) {
      const priorAction = await query<{ task_index: number }>(tx, sql`SELECT task_index FROM oid_run_task_action
        WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
      const priorClosure = await query<{ task_index: number; payload_hash: string }>(tx, sql`SELECT task_index,payload_hash FROM oid_run_task_closure
        WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
      if (priorAction.length || priorClosure.some((row) => row.task_index !== input.taskIndex || row.payload_hash !== payloadHash)) {
        throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'operationId was already used for a different task operation');
      }
      if (task.closure_reason === 'agent_finish' && task.closure_payload_hash !== payloadHash) {
        throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'The task was already finished with a different answer');
      }
      if (task.closure_reason !== 'agent_finish' && answer !== undefined) throw new HttpError(409, 'TASK_CLOSED', 'A deadline cutoff cannot accept a late answer');
      return finishView(task, true);
    }
    await assertRunNotInPlatformRecovery(tx, run.id);
    if (run.status !== 'running' || task.status !== 'active') throw new HttpError(409, 'TASK_NOT_ACTIVE', 'Only the current active task can be finished');
    const active = await query<{ task_index: number }>(tx, sql`SELECT task_index FROM oid_run_task WHERE run_id=${run.id} AND status='active' FOR UPDATE`);
    if (active.length !== 1 || active[0]!.task_index !== input.taskIndex) throw new HttpError(409, 'TASK_NOT_ACTIVE', 'Only the current active task can be finished');
    const priorAction = await query<{ id: string }>(tx, sql`SELECT id FROM oid_run_task_action WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
    if (priorAction.length) throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'operationId already identifies a task action');
    const priorClosure = await query<{ task_index: number; payload_hash: string }>(tx, sql`SELECT task_index,payload_hash FROM oid_run_task_closure
      WHERE run_id=${run.id} AND operation_id=${input.operationId}`);
    if (priorClosure.length) throw new HttpError(409, 'IDEMPOTENCY_CONFLICT', 'operationId already identifies a task closure');
    const now = await databaseNow(tx);
    const runDeadline = date(run.overall_deadline);
    const taskDeadline = date(task.deadline_at);
    if (!runDeadline || !taskDeadline) throw new HttpError(503, 'TASK_DEADLINE_UNAVAILABLE', 'The active task deadline is unavailable');
    const reason: FinishTaskResult['reason'] = now.getTime() >= runDeadline.getTime() ? 'run_deadline' :
      now.getTime() >= taskDeadline.getTime() ? 'task_deadline' : 'agent_finish';
    if (reason !== 'agent_finish') {
      const deadlineHash = hash({ runId: run.id, taskIndex: task.task_index, reason });
      task = await establishCutoff(tx, run, task, { reason, payloadHash: deadlineHash, actor: 'coordinator' }, now);
      return finishView(task, false);
    }
    task = await establishCutoff(tx, run, task, {
      reason, operationId: input.operationId, payloadHash, actor: 'agent', principal,
      ...(answer === undefined ? {} : { answer }),
    }, now);
    return finishView(task, false);
  });
}

/**
 * Establish task cutoffs whose persisted deadlines have elapsed. A coordinator
 * worker may call this after restart; it only commits the cutoff and finish
 * outbox record, leaving admitted commands for observation/reconciliation.
 */
export async function closeExpiredTaskActions(
  deps: TaskActionDependencies,
  limit = 50,
): Promise<{ closed: number; waitingReconciliation: number }> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
    throw new HttpError(400, 'INVALID_LIMIT', 'limit must be an integer from 1 to 500');
  }
  const candidates = await deps.db.execute(sql`SELECT r.id AS run_id,r.owner_id,r.agent_id,t.task_index
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
      WHERE r.status='running' AND t.status='active' AND t.closure_status='open'
        AND t.deadline_at IS NOT NULL AND r.overall_deadline IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM oid_run_platform_recovery recovery
          WHERE recovery.run_id=r.id AND recovery.status IN ('recovering','unknown','exhausted'))
        AND LEAST(t.deadline_at,r.overall_deadline)<=clock_timestamp()
      ORDER BY LEAST(t.deadline_at,r.overall_deadline),r.owner_id,r.id,t.task_index LIMIT ${limit}`) as unknown as Array<{
    run_id: string; owner_id: string; agent_id: string; task_index: number;
  }>;
  let closed = 0;
  let waitingReconciliation = 0;
  for (const candidate of candidates) {
    const outcome = await deps.db.transaction(async (tx) => {
      await lockOwner(tx, candidate.owner_id);
      const agents = await query<{ id: string }>(tx, sql`SELECT id FROM oid_agent WHERE id=${candidate.agent_id}
        AND owner_id=${candidate.owner_id} FOR NO KEY UPDATE`);
      if (!agents.length) return null;
      const runs = await query<RunRow>(tx, sql`SELECT * FROM oid_benchmark_run WHERE id=${candidate.run_id}
        AND owner_id=${candidate.owner_id} AND agent_id=${candidate.agent_id} FOR UPDATE`);
      const run = runs[0];
      if (!run || run.status !== 'running') return null;
      const tasks = await query<TaskRow>(tx, sql`SELECT run_id,task_index,task_id,status,started_at,deadline_at,
          accepted_action_sequence::text AS accepted_action_sequence,action_cutoff_sequence::text AS action_cutoff_sequence,
          reconciled_action_sequence::text AS reconciled_action_sequence,closure_status,closure_id,closure_operation_id,
          closure_payload_hash,closure_reason,closed_at FROM oid_run_task
        WHERE run_id=${run.id} AND task_index=${candidate.task_index} FOR UPDATE`);
      const task = tasks[0];
      if (!task || task.status !== 'active' || task.closure_status !== 'open') return null;
      const recoveryRows = await query<{ recovering: boolean }>(tx, sql`SELECT EXISTS(
        SELECT 1 FROM oid_run_platform_recovery recovery
        WHERE recovery.run_id=${run.id} AND recovery.status IN ('recovering','unknown','exhausted')) AS recovering`);
      if (recoveryRows[0]?.recovering) return null;
      const now = await databaseNow(tx);
      const runDeadline = date(run.overall_deadline);
      const taskDeadline = date(task.deadline_at);
      if (!runDeadline || !taskDeadline || (now < runDeadline && now < taskDeadline)) return null;
      const reason: FinishTaskResult['reason'] = now >= runDeadline ? 'run_deadline' : 'task_deadline';
      const cutoff = await establishCutoff(tx, run, task, {
        reason, payloadHash: hash({ runId: run.id, taskIndex: task.task_index, reason }), actor: 'coordinator',
      }, now);
      return { status: cutoff.closure_status };
    });
    if (outcome) {
      closed += 1;
      if (outcome.status !== 'closed') waitingReconciliation += 1;
    }
  }
  return { closed, waitingReconciliation };
}

/**
 * Record a trusted observer's receipt for an admitted command. This is an
 * internal adapter boundary, not an agent endpoint: callers must pass evidence
 * retained by the selected environment and must never resubmit the command.
 */
export async function recordTaskActionReceipt(
  deps: TaskActionDependencies,
  input: TaskActionReceiptInput,
): Promise<TaskActionReceiptResult> {
  if (input.toolResponse !== undefined && (!input.toolResponse || typeof input.toolResponse !== 'object' || Array.isArray(input.toolResponse))) {
    throw new HttpError(400, 'INVALID_ACTION_RECEIPT', 'The participant tool response must be a bounded JSON object');
  }
  const toolResponseJson = input.toolResponse === undefined ? null : canonicalTaskJson(input.toolResponse);
  const toolResponseHash = input.toolResponse === undefined ? null : hash(input.toolResponse);
  const evidencePath = input.evidencePath;
  if (evidencePath !== undefined && !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(evidencePath)) {
    throw new HttpError(400, 'INVALID_ACTION_RECEIPT', 'The evidence path must be a bounded repo-relative artifact path');
  }
  if (toolResponseJson !== null && Buffer.byteLength(toolResponseJson, 'utf8') > 1024 * 1024) {
    throw new HttpError(400, 'INVALID_ACTION_RECEIPT', 'The participant tool response exceeds the evidence bound');
  }
  if (!uuidPattern.test(input.actionId) || !/^[0-9a-f]{64}$/.test(input.evidenceHash) ||
    !['observed', 'rejected_before_execution', 'unknown'].includes(input.status) ||
    (input.transactionHash !== undefined && !/^0x[0-9a-f]{64}$/i.test(input.transactionHash))) {
    throw new HttpError(400, 'INVALID_ACTION_RECEIPT', 'The persisted observer receipt identity is invalid');
  }
  const initial = await deps.db.execute(sql`SELECT owner_id,agent_id,run_id,task_index FROM oid_run_task_action WHERE id=${input.actionId}`) as unknown as Array<{
    owner_id: string; agent_id: string; run_id: string; task_index: number;
  }>;
  if (!initial[0]) throw new HttpError(404, 'TASK_ACTION_NOT_FOUND', 'The admitted task action does not exist');
  const target = initial[0];
  return deps.db.transaction(async (tx) => {
    await lockOwner(tx, target.owner_id);
    const agentRows = await query<{ id: string }>(tx, sql`SELECT id FROM oid_agent WHERE id=${target.agent_id} AND owner_id=${target.owner_id} FOR NO KEY UPDATE`);
    if (!agentRows.length) throw new HttpError(404, 'AGENT_NOT_FOUND', 'The task action agent no longer exists');
    const runRows = await query<RunRow>(tx, sql`SELECT * FROM oid_benchmark_run WHERE id=${target.run_id} AND owner_id=${target.owner_id}
      AND agent_id=${target.agent_id} FOR UPDATE`);
    if (!runRows.length) throw new HttpError(404, 'RUN_NOT_FOUND', 'The task action run no longer exists');
    const taskRows = await query<TaskRow>(tx, sql`SELECT run_id,task_index,task_id,status,started_at,deadline_at,
        accepted_action_sequence::text AS accepted_action_sequence,action_cutoff_sequence::text AS action_cutoff_sequence,
        reconciled_action_sequence::text AS reconciled_action_sequence,closure_status,closure_id,closure_operation_id,
        closure_payload_hash,closure_reason,closed_at FROM oid_run_task
      WHERE run_id=${target.run_id} AND task_index=${target.task_index} FOR UPDATE`);
    const task = taskRows[0];
    const actionRows = await query<ActionRow>(tx, sql`SELECT id,run_id,task_index,task_id,action_sequence::text AS action_sequence,
        operation_id,payload_hash,accepted_at FROM oid_run_task_action WHERE id=${input.actionId} FOR UPDATE`);
    const action = actionRows[0];
    if (!task || !action || action.task_index !== target.task_index) throw new HttpError(404, 'TASK_ACTION_NOT_FOUND', 'The admitted task action does not exist');
    const currentRows = await query<{ receipt_revision: number; receipt_status: string; evidence_hash: string | null; evidence_path: string | null; transaction_hash: string | null; tool_response_hash: string | null }>(tx,
      sql`SELECT receipt_revision,receipt_status,evidence_hash,evidence_path,transaction_hash,tool_response_hash FROM oid_run_task_action_receipt WHERE action_id=${action.id} FOR UPDATE`);
    const current = currentRows[0];
    if (!current) throw new Error('Admitted task action has no mutable receipt projection');
    if (current.receipt_status === input.status && current.evidence_hash === input.evidenceHash &&
      current.evidence_path === (evidencePath ?? null) &&
      (current.transaction_hash?.toLowerCase() ?? null) === (input.transactionHash?.toLowerCase() ?? null) && current.tool_response_hash === toolResponseHash) {
      return receiptView(action, current.receipt_revision, current.receipt_status as TaskActionReceiptResult['receiptStatus'], task, true);
    }
    if (current.receipt_status !== 'pending' && current.receipt_status !== 'unknown') {
      throw new HttpError(409, 'ACTION_RECEIPT_CONFLICT', 'A resolved action receipt cannot be replaced');
    }
    if (current.receipt_status === 'unknown' && current.transaction_hash &&
      current.transaction_hash.toLowerCase() !== input.transactionHash?.toLowerCase()) {
      throw new HttpError(409, 'ACTION_RECEIPT_CONFLICT', 'Reconciliation must retain the original transaction identity');
    }
    const revision = current.receipt_revision + 1;
    const now = await databaseNow(tx);
    await tx.execute(sql`INSERT INTO oid_run_task_action_reconciliation(action_id,revision,receipt_status,evidence_hash,evidence_path,transaction_hash,tool_response_json,tool_response_hash,created_at)
      VALUES (${action.id},${revision},${input.status},${input.evidenceHash},${evidencePath ?? null},${input.transactionHash ?? null},${toolResponseJson}::jsonb,${toolResponseHash},${now.toISOString()})`);
    await tx.execute(sql`UPDATE oid_run_task_action_receipt SET receipt_revision=${revision},receipt_status=${input.status},
        evidence_hash=${input.evidenceHash},evidence_path=${evidencePath ?? null},transaction_hash=${input.transactionHash ?? null},tool_response_json=${toolResponseJson}::jsonb,
        tool_response_hash=${toolResponseHash},updated_at=${now.toISOString()}
      WHERE action_id=${action.id}`);
    await appendRunEvent(tx, target.run_id, 'executor', 'task.action.reconciled', {
      actionId: action.id, taskIndex: action.task_index, taskId: action.task_id,
      actionSequence: String(action.action_sequence), receiptRevision: revision, receiptStatus: input.status,
      evidenceHash: input.evidenceHash, transactionHash: input.transactionHash ?? null,
    });
    const updatedTask = await persistCutoffProgress(tx, task, now);
    return receiptView(action, revision, input.status, updatedTask, false);
  });
}

function receiptView(
  action: ActionRow,
  revision: number,
  status: TaskActionReceiptResult['receiptStatus'],
  task: TaskRow,
  replayed: boolean,
): TaskActionReceiptResult {
  return {
    actionId: action.id, actionSequence: String(action.action_sequence), receiptRevision: revision, receiptStatus: status,
    reconciledActionSequence: String(task.reconciled_action_sequence), closureStatus: task.closure_status, replayed,
  };
}
