import { createHash, randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { canonicalTaskJson } from './task-release.js';
import { recordTaskActionReceipt } from './task-action-service.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const ACTION_OPERATION_ID = /^[A-Za-z0-9_-]{12,128}$/;
const RECOVERY_WINDOW_MS = 180_000;
const MAX_CLOCK_EXCLUSION_MS = 180_000;
type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

type ActionStatus = 'observed' | 'rejected_before_execution' | 'unknown';
type PlatformRecoveryStatus = 'recovering' | 'recovered' | 'unknown' | 'exhausted' | 'refunded';
type RecoveryRow = {
  run_id: string; owner_id: string; agent_id: string; task_index: number; action_id: string;
  environment_id: string; operation_id: string; payload_hash: string; incident_evidence_hash: string;
  started_at: Date | string; deadline_at: Date | string; clock_excluded_ms: number; status: PlatformRecoveryStatus;
  latest_evidence_hash: string | null;
};

/**
 * AICODE-NOTE: This recovery service has no participant/admin-facing ingress. Its required
 * authority must verify evidence against the selected environment's durable operation source;
 * absent that provider, recovery/refund stays unavailable and unresolved actions stay unknown.
 *
 * Implementations must verify signatures/source identity and return normalized
 * facts. Merely parsing caller-supplied hashes is not platform attribution.
 * This interface is deliberately required by every entry point.
 */
export interface BetaPlatformRecoveryAuthority {
  verifyIncident(evidence: unknown): Promise<{
    runId: string; actionId: string; environmentId: string; operationId: string; payloadHash: string;
    evidenceHash: string; source: 'beta_platform_monitor';
  } | null>;
  verifyOperation(evidence: unknown): Promise<{
    runId: string; actionId: string; environmentId: string; operationId: string; payloadHash: string;
    evidenceHash: string; evidencePath: string; status: ActionStatus; clockExcludedMs: number;
    transactionHash?: string; toolResponse?: Record<string, unknown>;
  } | null>;
  verifyExhaustion(evidence: unknown): Promise<{
    runId: string; actionId: string; environmentId: string; operationId: string; payloadHash: string;
    evidenceHash: string; source: 'beta_platform_monitor';
  } | null>;
}

export interface BetaPlatformRecoveryDependencies {
  db: OwnerDatabase;
  authority: BetaPlatformRecoveryAuthority;
}

export const betaPlatformRecoveryMigrationStatements: readonly string[] = [
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_benchmark_run_platform_scope_uq ON oid_benchmark_run(id,owner_id,agent_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_run_task_action_platform_scope_uq ON oid_run_task_action(id,run_id)`,
  `CREATE TABLE IF NOT EXISTS oid_run_platform_recovery (
    action_id uuid PRIMARY KEY REFERENCES oid_run_task_action(id) ON DELETE RESTRICT,
    run_id uuid NOT NULL REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index BETWEEN 0 AND 11),
    environment_id text NOT NULL CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    incident_evidence_hash text NOT NULL CHECK(incident_evidence_hash ~ '^[0-9a-f]{64}$'),
    started_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL,
    clock_excluded_ms integer NOT NULL DEFAULT 0 CHECK(clock_excluded_ms BETWEEN 0 AND 180000),
    status text NOT NULL DEFAULT 'recovering' CHECK(status IN ('recovering','recovered','unknown','exhausted','refunded')),
    latest_evidence_hash text CHECK(latest_evidence_hash IS NULL OR latest_evidence_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_run_platform_recovery_action_run_fk FOREIGN KEY(action_id,run_id)
      REFERENCES oid_run_task_action(id,run_id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_platform_recovery_run_scope_fk FOREIGN KEY(run_id,owner_id,agent_id)
      REFERENCES oid_benchmark_run(id,owner_id,agent_id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_platform_recovery_deadline_ck CHECK(deadline_at >= started_at + interval '180 seconds')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_platform_recovery_due_idx ON oid_run_platform_recovery(status,deadline_at,run_id)`,
  `CREATE TABLE IF NOT EXISTS oid_run_platform_recovery_observation (
    action_id uuid NOT NULL REFERENCES oid_run_platform_recovery(action_id) ON DELETE RESTRICT,
    evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
    receipt_status text NOT NULL CHECK(receipt_status IN ('observed','rejected_before_execution','unknown')),
    clock_excluded_ms integer NOT NULL CHECK(clock_excluded_ms BETWEEN 0 AND 180000),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY(action_id,evidence_hash)
  )`,
  `CREATE TABLE IF NOT EXISTS oid_run_platform_refund (
    run_id uuid PRIMARY KEY REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
    operation_id text NOT NULL UNIQUE CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    bonus_refunded_units bigint NOT NULL CHECK(bonus_refunded_units >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_ledger_platform_refund_operation_uq
    ON oid_ledger_entry(operation_id) WHERE entry_type='refund' AND left(operation_id,7)='runref_'`,
  `CREATE OR REPLACE FUNCTION oid_reject_platform_recovery_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'platform recovery observations are append-only' USING ERRCODE='55000'; END; $$`,
  `DROP TRIGGER IF EXISTS oid_run_platform_recovery_observation_immutable_trg ON oid_run_platform_recovery_observation`,
  `CREATE TRIGGER oid_run_platform_recovery_observation_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_platform_recovery_observation
    FOR EACH ROW EXECUTE FUNCTION oid_reject_platform_recovery_mutation()`,
];

export async function migrateBetaPlatformRecovery(tx: { unsafe(query: string): Promise<unknown> }): Promise<void> {
  for (const statement of betaPlatformRecoveryMigrationStatements) await tx.unsafe(statement);
}

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('The PostgreSQL driver returned an unexpected platform recovery result');
  return value as T[];
}

async function query<T>(tx: Transaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

function hash(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}

function validHash(value: unknown): value is string { return typeof value === 'string' && HASH.test(value); }

function assertVerifiedIdentity(value: {
  runId: string; actionId: string; environmentId: string; operationId?: string; payloadHash?: string; evidenceHash: string;
}): void {
  if (!UUID.test(value.runId) || !UUID.test(value.actionId) ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.environmentId) || !validHash(value.evidenceHash) ||
      (value.operationId !== undefined && !ACTION_OPERATION_ID.test(value.operationId)) ||
      (value.payloadHash !== undefined && !validHash(value.payloadHash))) {
    throw new HttpError(400, 'PLATFORM_RECOVERY_EVIDENCE_INVALID', 'The verified platform recovery identity is malformed');
  }
}

async function lockOwner(tx: Transaction, ownerId: string): Promise<void> {
  const found = await query<{ id: string }>(tx, sql`SELECT id FROM oid_owner WHERE id=${ownerId} FOR NO KEY UPDATE`);
  if (!found.length) throw new HttpError(404, 'OWNER_NOT_FOUND', 'The run owner does not exist');
}

async function databaseNow(tx: Transaction): Promise<Date> {
  const found = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
  const value = found[0]?.now;
  const now = value instanceof Date ? value : new Date(String(value));
  if (!Number.isFinite(now.getTime())) throw new Error('PostgreSQL clock returned an invalid platform recovery timestamp');
  return now;
}

function persistedTimestamp(value: Date | string): Date {
  const timestamp = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(timestamp.getTime())) {
    throw new HttpError(409, 'PLATFORM_RECOVERY_LINEAGE_MISMATCH', 'Persisted platform recovery timestamps are invalid');
  }
  return timestamp;
}

async function appendEvent(tx: Transaction, runId: string, eventType: string, payload: Record<string, unknown>, now: Date): Promise<void> {
  const payloadHash = hash(payload);
  const duplicate = await query<{ id: string }>(tx, sql`SELECT id FROM oid_run_event
    WHERE run_id=${runId} AND event_type=${eventType} AND payload_hash=${payloadHash} LIMIT 1`);
  if (duplicate.length) return;
  const sequenceRows = await query<{ next_sequence: number }>(tx, sql`SELECT COALESCE(MAX(sequence),0)+1 AS next_sequence
    FROM oid_run_event WHERE run_id=${runId}`);
  await tx.execute(sql`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json,created_at)
    VALUES (${randomUUID()},${runId},${sequenceRows[0]?.next_sequence ?? 1},'worker',${eventType},${payloadHash},
      ${canonicalTaskJson(payload)}::jsonb,${now.toISOString()})`);
}

export function platformRecoveryWindowExpired(now: Date, deadline: Date): boolean {
  return Number.isFinite(now.getTime()) && Number.isFinite(deadline.getTime()) && now.getTime() >= deadline.getTime();
}

export function originalBonusRefundDeltas(expiresAt: Date | string | null, refundedAt: Date): {
  creditTo: 'available' | 'expired';
} {
  const expiry = expiresAt === null ? null : expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
  if (!Number.isFinite(refundedAt.getTime()) || (expiry && !Number.isFinite(expiry.getTime()))) {
    throw new Error('Invalid source bonus expiry timestamp');
  }
  return { creditTo: expiry && expiry.getTime() <= refundedAt.getTime() ? 'expired' : 'available' };
}

export function platformRefundEligible(input: {
  runStarted: boolean; cancellationReason: string | null; fenceEvidenceHash: string | null;
  fenceEventMatches: boolean; runHasLiveLease: boolean; windowExpired: boolean; recoveryStatus: string; originalReceiptStatus: string;
  noPendingRunActions: boolean;
}): boolean {
  return input.runStarted && input.cancellationReason === 'coordinator_platform_failure' &&
    validHash(input.fenceEvidenceHash) && input.fenceEventMatches && !input.runHasLiveLease && input.windowExpired &&
    ['recovering', 'unknown', 'exhausted', 'recovered'].includes(input.recoveryStatus) &&
    ['observed', 'rejected_before_execution', 'unknown'].includes(input.originalReceiptStatus) && input.noPendingRunActions;
}

export async function beginBetaPlatformRecovery(
  deps: BetaPlatformRecoveryDependencies,
  input: { runId: string; actionId: string; incidentEvidence: unknown },
): Promise<{ actionId: string; status: 'recovering' | 'recovered' | 'unknown' | 'exhausted' | 'refunded'; startedAt: string; deadlineAt: string; replayed: boolean }> {
  if (!UUID.test(input.runId) || !UUID.test(input.actionId)) throw new HttpError(400, 'INVALID_PLATFORM_RECOVERY_TARGET', 'Run and action UUIDs are required');
  const attested = await deps.authority.verifyIncident(input.incidentEvidence).catch(() => null);
  if (!attested || attested.source !== 'beta_platform_monitor') throw new HttpError(403, 'PLATFORM_INCIDENT_UNVERIFIED', 'A trusted beta platform incident attestation is required');
  assertVerifiedIdentity(attested);
  if (!ACTION_OPERATION_ID.test(attested.operationId) || !validHash(attested.payloadHash)) {
    throw new HttpError(400, 'PLATFORM_RECOVERY_EVIDENCE_INVALID', 'The verified incident must bind the original operation and payload');
  }
  if (attested.runId.toLowerCase() !== input.runId.toLowerCase() || attested.actionId.toLowerCase() !== input.actionId.toLowerCase()) {
    throw new HttpError(409, 'PLATFORM_RECOVERY_IDENTITY_MISMATCH', 'The incident attestation does not identify this exact original action');
  }

  return deps.db.transaction(async (tx) => {
    const hints = await query<{ owner_id: string }>(tx, sql`SELECT owner_id FROM oid_benchmark_run WHERE id=${input.runId}`);
    const ownerId = hints[0]?.owner_id;
    if (!ownerId) throw new HttpError(404, 'RUN_NOT_FOUND', 'The run does not exist');
    await lockOwner(tx, ownerId);
    const joined = await query<{ run_id: string; owner_id: string; agent_id: string; run_agent_id: string; task_index: number; action_id: string;
      environment_id: string; operation_id: string; payload_hash: string; run_status: string; receipt_status: string;
      outbox_status: string }>(tx, sql`SELECT a.run_id,a.owner_id,a.agent_id,r.agent_id AS run_agent_id,a.task_index,a.id AS action_id,a.environment_id,
        a.operation_id,a.payload_hash,r.status AS run_status,receipt.receipt_status,outbox.status AS outbox_status
      FROM oid_run_task_action a JOIN oid_benchmark_run r ON r.id=a.run_id
      JOIN oid_run_task_action_receipt receipt ON receipt.action_id=a.id
      JOIN oid_run_task_action_outbox outbox ON outbox.action_id=a.id
      WHERE a.id=${input.actionId} AND a.run_id=${input.runId} FOR UPDATE OF r,a,receipt,outbox`);
    const action = joined[0];
    if (!action || action.owner_id !== ownerId || action.agent_id !== action.run_agent_id || action.environment_id !== attested.environmentId ||
        action.operation_id !== attested.operationId || action.payload_hash !== attested.payloadHash) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_NOT_ELIGIBLE', 'Recovery requires this run’s delivered, unresolved original action');
    }
    const existing = await query<RecoveryRow>(tx, sql`SELECT * FROM oid_run_platform_recovery WHERE action_id=${action.action_id} FOR UPDATE`);
    if (existing[0]) {
      const row = existing[0];
      if (row.run_id !== action.run_id || row.owner_id !== action.owner_id || row.agent_id !== action.agent_id ||
          row.task_index !== action.task_index || row.operation_id !== action.operation_id || row.payload_hash !== action.payload_hash ||
          row.incident_evidence_hash !== attested.evidenceHash || row.environment_id !== action.environment_id ||
          !['recovering', 'recovered', 'unknown', 'exhausted', 'refunded'].includes(row.status)) {
        throw new HttpError(409, 'PLATFORM_RECOVERY_CONFLICT', 'This original action already has a different recovery lineage');
      }
      const startedAt = persistedTimestamp(row.started_at);
      const deadlineAt = persistedTimestamp(row.deadline_at);
      const startedEvent = await query<{ id: string }>(tx, sql`SELECT id FROM oid_run_event
        WHERE run_id=${action.run_id} AND event_type='run.platform_recovery_started'
          AND payload_json->>'actionId'=${action.action_id} AND payload_json->>'operationId'=${action.operation_id}
          AND payload_json->>'incidentEvidenceHash'=${row.incident_evidence_hash} LIMIT 1`);
      if (!startedEvent.length || deadlineAt.getTime() !== startedAt.getTime() + RECOVERY_WINDOW_MS ||
          !Number.isSafeInteger(row.clock_excluded_ms) || row.clock_excluded_ms < 0 || row.clock_excluded_ms > MAX_CLOCK_EXCLUSION_MS ||
          row.latest_evidence_hash !== null && !validHash(row.latest_evidence_hash)) {
        throw new HttpError(409, 'PLATFORM_RECOVERY_LINEAGE_MISMATCH', 'The persisted recovery is missing its original event or valid bounds');
      }
      return { actionId: row.action_id, status: row.status as 'recovering' | 'recovered' | 'unknown' | 'exhausted' | 'refunded',
        startedAt: startedAt.toISOString(), deadlineAt: deadlineAt.toISOString(), replayed: true };
    }
    if (action.run_status !== 'running' || !['pending', 'unknown'].includes(action.receipt_status) || action.outbox_status !== 'delivered') {
      throw new HttpError(409, 'PLATFORM_RECOVERY_NOT_ELIGIBLE', 'Recovery requires this run’s delivered, unresolved original action');
    }
    const now = await databaseNow(tx);
    const deadline = new Date(now.getTime() + RECOVERY_WINDOW_MS);
    await tx.execute(sql`INSERT INTO oid_run_platform_recovery(action_id,run_id,owner_id,agent_id,task_index,environment_id,
      operation_id,payload_hash,incident_evidence_hash,started_at,deadline_at,status,created_at,updated_at)
      VALUES (${action.action_id},${action.run_id},${action.owner_id},${action.agent_id},${action.task_index},${action.environment_id},
        ${action.operation_id},${action.payload_hash},${attested.evidenceHash},${now.toISOString()},${deadline.toISOString()},'recovering',${now.toISOString()},${now.toISOString()})`);
    await appendEvent(tx, action.run_id, 'run.platform_recovery_started', {
      actionId: action.action_id, operationId: action.operation_id, taskIndex: action.task_index,
      incidentEvidenceHash: attested.evidenceHash, deadlineAt: deadline.toISOString(),
    }, now);
    return { actionId: action.action_id, status: 'recovering', startedAt: now.toISOString(), deadlineAt: deadline.toISOString(), replayed: false };
  });
}

export async function recordBetaPlatformRecoveryObservation(
  deps: BetaPlatformRecoveryDependencies,
  input: { actionId: string; evidence: unknown },
): Promise<{ actionId: string; status: 'recovering' | 'recovered' | 'unknown' | 'exhausted'; receiptStatus: ActionStatus; replayed: boolean }> {
  if (!UUID.test(input.actionId)) throw new HttpError(400, 'INVALID_PLATFORM_RECOVERY_TARGET', 'An action UUID is required');
  const attested = await deps.authority.verifyOperation(input.evidence).catch(() => null);
  if (!attested) throw new HttpError(403, 'PLATFORM_OPERATION_UNVERIFIED', 'A trusted observation of the original operation is required');
  assertVerifiedIdentity(attested);
  if (attested.actionId.toLowerCase() !== input.actionId.toLowerCase() ||
      !ACTION_OPERATION_ID.test(attested.operationId) || !validHash(attested.payloadHash) ||
      !Number.isSafeInteger(attested.clockExcludedMs) || attested.clockExcludedMs < 0 || attested.clockExcludedMs > MAX_CLOCK_EXCLUSION_MS ||
      !['observed', 'rejected_before_execution', 'unknown'].includes(attested.status) ||
      typeof attested.evidencePath !== 'string' || !/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(attested.evidencePath)) {
    throw new HttpError(400, 'PLATFORM_OPERATION_EVIDENCE_INVALID', 'The operation observation is malformed or outside its evidence bounds');
  }
  if ((attested.transactionHash !== undefined && !/^0x[0-9a-f]{64}$/i.test(attested.transactionHash)) ||
      (attested.status === 'rejected_before_execution' && attested.transactionHash !== undefined)) {
    throw new HttpError(400, 'PLATFORM_OPERATION_EVIDENCE_INVALID', 'The original transaction identity is malformed or conflicts with a pre-execution rejection');
  }

  const binding = await deps.db.execute(sql`SELECT action.owner_id,action.run_id,action.task_index,action.environment_id,action.operation_id,
      action.payload_hash,run.status AS run_status,recovery.status AS recovery_status
    FROM oid_run_task_action action JOIN oid_benchmark_run run ON run.id=action.run_id
      AND run.owner_id=action.owner_id AND run.agent_id=action.agent_id
    JOIN oid_run_platform_recovery recovery ON recovery.action_id=action.id
    WHERE action.id=${input.actionId}`) as unknown as Array<{
      owner_id: string; run_id: string; task_index: number; environment_id: string; operation_id: string; payload_hash: string;
      run_status: string; recovery_status: string;
    }>;
  const action = binding[0];
  if (!action) throw new HttpError(404, 'TASK_ACTION_NOT_FOUND', 'The original admitted action does not exist');
  if (action.run_status === 'failed' || action.recovery_status === 'refunded') {
    throw new HttpError(409, 'PLATFORM_RECOVERY_SETTLED', 'A failed or refunded run cannot accept additional recovery observations');
  }
  if (attested.actionId.toLowerCase() !== input.actionId.toLowerCase() ||
      action.run_id.toLowerCase() !== attested.runId.toLowerCase() || action.environment_id !== attested.environmentId ||
      action.operation_id !== attested.operationId || action.payload_hash !== attested.payloadHash) {
    throw new HttpError(409, 'PLATFORM_RECOVERY_IDENTITY_MISMATCH', 'The observation does not match the original action, operation and payload');
  }
  const recoveryBinding = await deps.db.execute(sql`SELECT action_id FROM oid_run_platform_recovery
    WHERE action_id=${input.actionId} AND run_id=${action.run_id} AND operation_id=${action.operation_id}
      AND payload_hash=${action.payload_hash} AND environment_id=${action.environment_id}`) as unknown as Array<{ action_id: string }>;
  if (!recoveryBinding.length) throw new HttpError(409, 'PLATFORM_RECOVERY_NOT_FOUND', 'The exact original action has no active platform recovery record');

  const observationState = await deps.db.transaction(async (tx) => {
    await lockOwner(tx, action.owner_id);
    const runRows = await query<{ status: string; overall_deadline: Date | string | null }>(tx, sql`SELECT status,overall_deadline
      FROM oid_benchmark_run WHERE id=${action.run_id} AND owner_id=${action.owner_id} FOR UPDATE`);
    const taskRows = await query<{ status: string; deadline_at: Date | string | null; closure_status: string }>(tx, sql`SELECT status,deadline_at,closure_status
      FROM oid_run_task WHERE run_id=${action.run_id} AND task_index=${action.task_index} FOR UPDATE`);
    const recoveryRows = await query<RecoveryRow>(tx, sql`SELECT * FROM oid_run_platform_recovery
      WHERE action_id=${input.actionId} AND run_id=${action.run_id} FOR UPDATE`);
    const recovery = recoveryRows[0];
    if (!recovery || recovery.operation_id !== attested.operationId || recovery.payload_hash !== attested.payloadHash ||
        recovery.environment_id !== attested.environmentId) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_NOT_FOUND', 'The exact original action has no active platform recovery record');
    }
    const existing = await query<{ evidence_hash: string; receipt_status: string }>(tx, sql`SELECT evidence_hash,receipt_status
      FROM oid_run_platform_recovery_observation WHERE action_id=${input.actionId} AND evidence_hash=${attested.evidenceHash}`);
    if (existing[0]) {
      if (existing[0].receipt_status !== attested.status) throw new HttpError(409, 'PLATFORM_RECOVERY_OBSERVATION_CONFLICT', 'The same evidence hash has conflicting status');
      return { replayed: true as const };
    }
    const now = await databaseNow(tx);
    const excluded = recovery.clock_excluded_ms + attested.clockExcludedMs;
    if (excluded > MAX_CLOCK_EXCLUSION_MS) throw new HttpError(409, 'PLATFORM_RECOVERY_CLOCK_BOUND_EXCEEDED', 'Verified recovery clock exclusion exceeds its bound');
    if (attested.clockExcludedMs > 0 && runRows[0]?.status === 'running' && taskRows[0]?.status === 'active' &&
        taskRows[0]?.closure_status === 'open') {
      if (runRows[0].overall_deadline === null || taskRows[0].deadline_at === null) {
        throw new HttpError(409, 'PLATFORM_RECOVERY_CLOCK_DEADLINE_MISSING', 'Active task and run deadlines are required for verified clock exclusion');
      }
      await tx.execute(sql`UPDATE oid_benchmark_run SET overall_deadline=overall_deadline+(${attested.clockExcludedMs} * interval '1 millisecond')
        WHERE id=${action.run_id} AND owner_id=${action.owner_id} AND status='running' AND overall_deadline IS NOT NULL`);
      await tx.execute(sql`UPDATE oid_run_task SET deadline_at=deadline_at+(${attested.clockExcludedMs} * interval '1 millisecond')
        WHERE run_id=${action.run_id} AND task_index=${action.task_index}
          AND status='active' AND closure_status='open' AND deadline_at IS NOT NULL`);
      await appendEvent(tx, action.run_id, 'run.platform_recovery_clock_excluded', {
        actionId: input.actionId, operationId: attested.operationId, evidenceHash: attested.evidenceHash,
        clockExcludedMs: attested.clockExcludedMs,
      }, now);
    }
    await tx.execute(sql`INSERT INTO oid_run_platform_recovery_observation(action_id,evidence_hash,receipt_status,clock_excluded_ms,observed_at)
      VALUES (${input.actionId},${attested.evidenceHash},${attested.status},${attested.clockExcludedMs},${now.toISOString()})`);
    const updated = await query<{ action_id: string }>(tx, sql`UPDATE oid_run_platform_recovery SET clock_excluded_ms=${excluded},
      deadline_at=started_at + interval '180 seconds',
      updated_at=${now.toISOString()}
      WHERE action_id=${input.actionId} RETURNING action_id`);
    if (updated.length !== 1) throw new Error('Platform recovery record disappeared during observation');
    return { replayed: false as const };
  });

  // This existing internal boundary only updates the receipt for the original action ID;
  // it never resubmits its command or invents a replacement operation. Deadline exclusions
  // are committed first while active-recovery guards prevent finish/deadline races.
  const receipt = await recordTaskActionReceipt({ db: deps.db }, {
    actionId: input.actionId, status: attested.status, evidenceHash: attested.evidenceHash,
    evidencePath: attested.evidencePath,
    ...(attested.transactionHash ? { transactionHash: attested.transactionHash } : {}),
    ...(attested.toolResponse ? { toolResponse: attested.toolResponse } : {}),
  });

  return deps.db.transaction(async (tx) => {
    await lockOwner(tx, action.owner_id);
    const recoveryRows = await query<RecoveryRow>(tx, sql`SELECT * FROM oid_run_platform_recovery
      WHERE action_id=${input.actionId} AND run_id=${action.run_id} FOR UPDATE`);
    const recovery = recoveryRows[0];
    if (!recovery || recovery.operation_id !== attested.operationId || recovery.payload_hash !== attested.payloadHash ||
        recovery.environment_id !== attested.environmentId) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_NOT_FOUND', 'The exact original action has no active platform recovery record');
    }
    const now = await databaseNow(tx);
    const deadline = persistedTimestamp(recovery.deadline_at);
    if (deadline.getTime() !== persistedTimestamp(recovery.started_at).getTime() + RECOVERY_WINDOW_MS) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_LINEAGE_MISMATCH', 'The persisted recovery deadline is outside the fixed recovery bound');
    }
    const windowExpired = platformRecoveryWindowExpired(now, deadline);
    const status = windowExpired ? 'exhausted' : attested.status === 'unknown' ? 'unknown' : 'recovered';
    const updated = await query<{ action_id: string }>(tx, sql`UPDATE oid_run_platform_recovery SET status=${status},
      latest_evidence_hash=${attested.evidenceHash},updated_at=${now.toISOString()}
      WHERE action_id=${input.actionId} RETURNING action_id`);
    if (updated.length !== 1) throw new Error('Platform recovery record disappeared during observation');
    await appendEvent(tx, action.run_id, 'run.platform_recovery_observed', {
      actionId: input.actionId, operationId: attested.operationId, receiptStatus: attested.status,
      evidenceHash: attested.evidenceHash, clockExcludedMs: attested.clockExcludedMs,
    }, now);
    return { actionId: input.actionId, status, receiptStatus: receipt.receiptStatus, replayed: observationState.replayed };
  });
}

export async function finalizeExhaustedBetaPlatformFailure(
  deps: BetaPlatformRecoveryDependencies,
  input: { runId: string; actionId: string; exhaustionEvidence: unknown },
): Promise<{ runId: string; status: 'failed' | 'unknown'; bonusRefundedUnits: string; replayed: boolean }> {
  if (!UUID.test(input.runId) || !UUID.test(input.actionId)) throw new HttpError(400, 'INVALID_PLATFORM_RECOVERY_TARGET', 'Run and action UUIDs are required');
  const attested = await deps.authority.verifyExhaustion(input.exhaustionEvidence).catch(() => null);
  if (!attested || attested.source !== 'beta_platform_monitor') throw new HttpError(403, 'PLATFORM_FAILURE_UNVERIFIED', 'A trusted exhausted platform failure attestation is required');
  assertVerifiedIdentity(attested);
  if (attested.runId.toLowerCase() !== input.runId.toLowerCase() || attested.actionId.toLowerCase() !== input.actionId.toLowerCase() ||
      !ACTION_OPERATION_ID.test(attested.operationId) || !validHash(attested.payloadHash)) {
    throw new HttpError(409, 'PLATFORM_RECOVERY_IDENTITY_MISMATCH', 'The exhausted failure does not identify the original run operation');
  }

  return deps.db.transaction(async (tx) => {
    const hints = await query<{ owner_id: string }>(tx, sql`SELECT owner_id FROM oid_benchmark_run WHERE id=${input.runId}`);
    const ownerId = hints[0]?.owner_id;
    if (!ownerId) throw new HttpError(404, 'RUN_NOT_FOUND', 'The run does not exist');
    await lockOwner(tx, ownerId);
    const runRows = await query<{ id: string; owner_id: string; status: string; terminal_reason: string | null; started_at: Date | string | null;
      cancellation_reason: string | null; cancellation_evidence_hash: string | null }>(tx, sql`SELECT id,owner_id,status,terminal_reason,started_at,
      cancellation_reason,cancellation_evidence_hash FROM oid_benchmark_run WHERE id=${input.runId} AND owner_id=${ownerId} FOR UPDATE`);
    const run = runRows[0];
    if (!run) throw new HttpError(404, 'RUN_NOT_FOUND', 'The run does not exist');
    if (run.cancellation_reason !== 'coordinator_platform_failure' ||
        !validHash(run.cancellation_evidence_hash) || run.started_at === null) {
      throw new HttpError(409, 'PLATFORM_FAILURE_NOT_FENCED', 'A post-start platform failure must be cancelled and exactly fenced before refund evaluation');
    }
    const recoveryRows = await query<RecoveryRow>(tx, sql`SELECT * FROM oid_run_platform_recovery
      WHERE action_id=${input.actionId} AND run_id=${run.id} FOR UPDATE`);
    const recovery = recoveryRows[0];
    if (!recovery || recovery.run_id !== run.id || recovery.owner_id !== ownerId || recovery.action_id !== input.actionId ||
        recovery.operation_id !== attested.operationId || recovery.payload_hash !== attested.payloadHash ||
        recovery.environment_id !== attested.environmentId) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_LINEAGE_MISMATCH', 'The attestation does not match a persisted recovery for this original operation');
    }
    const now = await databaseNow(tx);
    const deadline = persistedTimestamp(recovery.deadline_at);
    if (!platformRecoveryWindowExpired(now, deadline)) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_WINDOW_OPEN', 'The bounded original-operation recovery window has not expired');
    }
    const actionRows = await query<{ receipt_status: string }>(tx, sql`SELECT receipt.receipt_status
      FROM oid_run_task_action action JOIN oid_benchmark_run action_run ON action_run.id=action.run_id
        AND action_run.owner_id=action.owner_id AND action_run.agent_id=action.agent_id
      JOIN oid_run_task_action_receipt receipt ON receipt.action_id=action.id
      WHERE action.id=${input.actionId} AND action.run_id=${run.id} AND action.operation_id=${attested.operationId} AND action.payload_hash=${attested.payloadHash}
        AND action.environment_id=${attested.environmentId} FOR UPDATE OF action,receipt`);
    const originalStatus = actionRows[0]?.receipt_status ?? 'missing';
    const pendingRows = await query<{ pending: boolean; unknown_count: number }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_task_action action LEFT JOIN oid_run_task_action_receipt receipt ON receipt.action_id=action.id
      WHERE action.run_id=${run.id} AND (receipt.action_id IS NULL OR receipt.receipt_status='pending')) AS pending,
      (SELECT COUNT(*)::int FROM oid_run_task_action action JOIN oid_run_task_action_receipt receipt ON receipt.action_id=action.id
        WHERE action.run_id=${run.id} AND receipt.receipt_status='unknown') AS unknown_count`);
    const leaseRows = await query<{ live: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_task_environment_lease lease JOIN oid_task_preparation_intent intent
        ON intent.preparation_id=lease.preparation_id WHERE intent.run_id=${run.id} AND lease.state='leased') AS live`);
    const fenceRows = await query<{ matches: boolean }>(tx, sql`SELECT EXISTS(
      SELECT 1 FROM oid_run_event event WHERE event.run_id=${run.id} AND event.event_type='run.cancelled.after_start'
        AND event.payload_json->>'reason'='coordinator_platform_failure'
        AND event.payload_json->>'fenceEvidenceHash'=${run.cancellation_evidence_hash}) AS matches`);
    const recoveryStartEvents = await query<{ id: string }>(tx, sql`SELECT id FROM oid_run_event
      WHERE run_id=${run.id} AND event_type='run.platform_recovery_started'
        AND payload_json->>'actionId'=${input.actionId} AND payload_json->>'operationId'=${attested.operationId}
        AND payload_json->>'incidentEvidenceHash'=${recovery.incident_evidence_hash} LIMIT 1`);
    if (!recoveryStartEvents.length || originalStatus === 'missing') {
      throw new HttpError(409, 'PLATFORM_RECOVERY_LINEAGE_MISMATCH', 'The original recovery event or action receipt is missing');
    }

    const priorRefund = await query<{ evidence_hash: string; operation_id: string; bonus_refunded_units: string | bigint }>(tx,
      sql`SELECT evidence_hash,operation_id,bonus_refunded_units::text FROM oid_run_platform_refund WHERE run_id=${run.id}`);
    if (priorRefund[0]) {
      const refundOperationId = `runref_${run.id.replaceAll('-', '')}`;
      if (priorRefund[0].evidence_hash !== attested.evidenceHash || priorRefund[0].operation_id !== refundOperationId) {
        throw new HttpError(409, 'PLATFORM_REFUND_CONFLICT', 'This run already has a refund bound to different evidence or operation');
      }
      if (run.status !== 'failed' || run.terminal_reason !== 'platform_failure_recovery_exhausted' || recovery.status !== 'refunded' ||
          recovery.latest_evidence_hash !== attested.evidenceHash || !['observed', 'rejected_before_execution', 'unknown'].includes(originalStatus) ||
          pendingRows[0]?.pending !== false || leaseRows[0]?.live !== false || fenceRows[0]?.matches !== true) {
        throw new HttpError(409, 'PLATFORM_REFUND_LINEAGE_MISMATCH', 'The settled refund is missing its original run, action, fence or recovery state');
      }

      const reservations = await query<{ bonus_grant_id: string; amount_units: string; expires_at: Date | string | null;
        reservation_state: string; debit_count: number; debited_units: string | null }>(tx, sql`SELECT reservation.bonus_grant_id,
        reservation.amount_units::text,bonus.expires_at,reservation.state AS reservation_state,
        (SELECT COUNT(*)::int FROM oid_ledger_entry entry WHERE entry.operation_id=${`rundeb_${run.id.replaceAll('-', '')}`}
          AND entry.entry_type='debit' AND entry.source_kind='tester_bonus' AND entry.bonus_grant_id=reservation.bonus_grant_id) AS debit_count,
        (SELECT COALESCE(SUM(entry.amount_units),0)::text FROM oid_ledger_entry entry
          WHERE entry.operation_id=${`rundeb_${run.id.replaceAll('-', '')}`} AND entry.entry_type='debit'
            AND entry.source_kind='tester_bonus' AND entry.bonus_grant_id=reservation.bonus_grant_id) AS debited_units
        FROM oid_run_reservation reservation JOIN oid_bonus_grant bonus ON bonus.id=reservation.bonus_grant_id
        WHERE reservation.run_id=${run.id} AND reservation.source_kind='tester_bonus'
        ORDER BY reservation.bonus_grant_id FOR UPDATE OF reservation,bonus`);
      const allBonusDebitRows = await query<{ count: number }>(tx, sql`SELECT COUNT(*)::int AS count FROM oid_ledger_entry
        WHERE operation_id=${`rundeb_${run.id.replaceAll('-', '')}`} AND entry_type='debit' AND source_kind='tester_bonus'`);
      if ((allBonusDebitRows[0]?.count ?? -1) !== reservations.length) {
        throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The original bonus debit ledger does not map one-to-one to this run’s reserved grant sources');
      }

      const refundPrefix = `${refundOperationId}_`;
      const refundedSources = await query<{ bonus_grant_id: string | null; operation_id: string; source_kind: string;
        amount_units: string; available_delta_units: string; expired_delta_units: string; created_at: Date | string }>(tx,
        sql`SELECT bonus_grant_id,operation_id,source_kind,amount_units::text,available_delta_units::text,expired_delta_units::text,created_at
          FROM oid_ledger_entry WHERE left(operation_id,length(${refundPrefix}))=${refundPrefix} AND entry_type='refund'
          ORDER BY bonus_grant_id FOR UPDATE`);
      if (refundedSources.length !== reservations.length) {
        throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The persisted refund does not match the original bonus source count');
      }
      let bonusRefunded = 0n;
      const refundedGrantIds = new Set<string>();
      for (const refunded of refundedSources) {
        const source = reservations.find((candidate) => candidate.bonus_grant_id === refunded.bonus_grant_id);
        if (!source || refundedGrantIds.has(source.bonus_grant_id) || refunded.source_kind !== 'tester_bonus' ||
            refunded.operation_id !== `${refundOperationId}_${source.bonus_grant_id.replaceAll('-', '')}`) {
          throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'A refund entry does not match its original bonus grant');
        }
        const amount = BigInt(source.amount_units);
        if (source.reservation_state !== 'debited' || source.debit_count !== 1 || amount <= 0n || BigInt(source.debited_units ?? '0') !== amount ||
            BigInt(refunded.amount_units) !== amount) {
          throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The original bonus reservation and refund do not match their committed debit');
        }
        const creditTo = originalBonusRefundDeltas(source.expires_at, persistedTimestamp(refunded.created_at)).creditTo;
        const expectedAvailable = creditTo === 'available' ? amount.toString() : '0';
        const expectedExpired = creditTo === 'expired' ? amount.toString() : '0';
        if (BigInt(refunded.available_delta_units) !== BigInt(expectedAvailable) || BigInt(refunded.expired_delta_units) !== BigInt(expectedExpired)) {
          throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'A refund entry does not preserve its original bonus expiry outcome');
        }
        refundedGrantIds.add(source.bonus_grant_id);
        bonusRefunded += amount;
      }
      if (bonusRefunded.toString() !== String(priorRefund[0].bonus_refunded_units)) {
        throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The refund total does not match its persisted source entries');
      }

      const settledEvent = await query<{ id: string }>(tx, sql`SELECT id FROM oid_run_event
        WHERE run_id=${run.id} AND event_type='run.failed.platform_recovery_exhausted'
          AND payload_json->>'actionId'=${input.actionId} AND payload_json->>'operationId'=${attested.operationId}
          AND payload_json->>'evidenceHash'=${attested.evidenceHash}
          AND payload_json->>'bonusRefundedUnits'=${bonusRefunded.toString()}
          AND payload_json->>'refundedSources'=${String(reservations.length)} AND payload_json->>'cashRefundedUnits'='0' LIMIT 1`);
      const audit = await query<{ id: string }>(tx, sql`SELECT id FROM oid_ledger_audit
        WHERE operation_id=${refundOperationId} AND event_type='run_platform_failure_refunded'
          AND actor_owner_id=${ownerId} AND subject_owner_id=${ownerId}
          AND metadata->>'runId'=${run.id} AND metadata->>'evidenceHash'=${attested.evidenceHash}
          AND metadata->>'bonusRefundedUnits'=${bonusRefunded.toString()}
          AND metadata->>'originalActionId'=${input.actionId} AND metadata->>'originalOperationId'=${attested.operationId} LIMIT 1`);
      if (!settledEvent.length || !audit.length) {
        throw new HttpError(409, 'PLATFORM_REFUND_LINEAGE_MISMATCH', 'The settled refund is missing its durable run event or audit receipt');
      }
      return { runId: run.id, status: 'failed' as const, bonusRefundedUnits: bonusRefunded.toString(), replayed: true };
    }

    if (!['cancelled', 'unknown'].includes(run.status)) {
      throw new HttpError(409, 'PLATFORM_FAILURE_NOT_FENCED', 'A post-start platform failure must be cancelled and exactly fenced before refund evaluation');
    }
    const eligible = platformRefundEligible({ runStarted: run.started_at !== null,
      cancellationReason: run.cancellation_reason, fenceEvidenceHash: run.cancellation_evidence_hash,
      fenceEventMatches: fenceRows[0]?.matches === true, runHasLiveLease: leaseRows[0]?.live === true,
      windowExpired: true, recoveryStatus: recovery.status, originalReceiptStatus: originalStatus,
      noPendingRunActions: pendingRows[0]?.pending === false });

    if (leaseRows[0]?.live === true) {
      throw new HttpError(409, 'PLATFORM_FAILURE_FENCE_INCOMPLETE', 'A live task environment lease still prevents failure settlement');
    }

    if (!eligible || !['cancelled', 'unknown'].includes(run.status)) {
      await tx.execute(sql`UPDATE oid_run_platform_recovery SET status='unknown',latest_evidence_hash=${attested.evidenceHash},
        updated_at=${now.toISOString()} WHERE action_id=${input.actionId}`);
      if (run.status === 'cancelled') {
        await tx.execute(sql`UPDATE oid_benchmark_run SET status='unknown',terminal_reason='platform_recovery_unresolved_operation'
          WHERE id=${run.id} AND status='cancelled' AND cancellation_reason='coordinator_platform_failure'`);
      }
      await appendEvent(tx, run.id, 'run.platform_recovery_unknown', {
        actionId: input.actionId, operationId: attested.operationId, evidenceHash: attested.evidenceHash,
        originalReceiptStatus: originalStatus, pendingActionExists: pendingRows[0]?.pending === true,
        unknownActionCount: pendingRows[0]?.unknown_count ?? null,
        liveTaskLeaseExists: Boolean(leaseRows[0]?.live), fenceEventMatches: fenceRows[0]?.matches === true,
      }, now);
      return { runId: run.id, status: 'unknown', bonusRefundedUnits: '0', replayed: false };
    }

    const reservations = await query<{ bonus_grant_id: string; amount_units: string; expires_at: Date | string | null;
      reservation_state: string; debit_count: number; debited_units: string | null }>(tx, sql`SELECT reservation.bonus_grant_id,
      reservation.amount_units::text,bonus.expires_at,reservation.state AS reservation_state,
      (SELECT COUNT(*)::int FROM oid_ledger_entry entry WHERE entry.operation_id=${`rundeb_${run.id.replaceAll('-', '')}`}
        AND entry.entry_type='debit' AND entry.source_kind='tester_bonus' AND entry.bonus_grant_id=reservation.bonus_grant_id) AS debit_count,
      (SELECT COALESCE(SUM(entry.amount_units),0)::text FROM oid_ledger_entry entry
        WHERE entry.operation_id=${`rundeb_${run.id.replaceAll('-', '')}`} AND entry.entry_type='debit'
          AND entry.source_kind='tester_bonus' AND entry.bonus_grant_id=reservation.bonus_grant_id) AS debited_units
      FROM oid_run_reservation reservation JOIN oid_bonus_grant bonus ON bonus.id=reservation.bonus_grant_id
      WHERE reservation.run_id=${run.id} AND reservation.source_kind='tester_bonus'
      ORDER BY reservation.bonus_grant_id FOR UPDATE OF reservation,bonus`);
    const allBonusDebitRows = await query<{ count: number }>(tx, sql`SELECT COUNT(*)::int AS count FROM oid_ledger_entry
      WHERE operation_id=${`rundeb_${run.id.replaceAll('-', '')}`} AND entry_type='debit' AND source_kind='tester_bonus'`);
    if ((allBonusDebitRows[0]?.count ?? -1) !== reservations.length) {
      throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The original bonus debit ledger does not map one-to-one to this run’s reserved grant sources');
    }
    const refundOperationId = `runref_${run.id.replaceAll('-', '')}`;
    let bonusRefunded = 0n;
    for (const source of reservations) {
      const amount = BigInt(source.amount_units);
      if (source.reservation_state !== 'debited' || source.debit_count !== 1 || amount <= 0n || BigInt(source.debited_units ?? '0') !== amount) {
        throw new HttpError(409, 'PLATFORM_REFUND_SOURCE_MISMATCH', 'The original bonus reservation does not match its committed debit');
      }
      const expired = originalBonusRefundDeltas(source.expires_at, now).creditTo === 'expired';
      const sourceOperationId = `${refundOperationId}_${source.bonus_grant_id.replaceAll('-', '')}`;
      await tx.execute(sql`INSERT INTO oid_ledger_entry(id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,
        amount_units,available_delta_units,reserved_delta_units,expired_delta_units,cash_provenance,reason,created_at)
        VALUES (${randomUUID()},${ownerId},${ownerId},${source.bonus_grant_id},${sourceOperationId},'refund','tester_bonus',
          ${amount.toString()},${expired ? '0' : amount.toString()},0,${expired ? amount.toString() : '0'},NULL,
          'beta platform failure after bounded original-operation recovery',${now.toISOString()})`);
      bonusRefunded += amount;
    }
    await tx.execute(sql`INSERT INTO oid_run_platform_refund(run_id,evidence_hash,operation_id,bonus_refunded_units,created_at)
      VALUES (${run.id},${attested.evidenceHash},${refundOperationId},${bonusRefunded.toString()},${now.toISOString()})`);
    const recoveryFinalized = await query<{ action_id: string }>(tx, sql`UPDATE oid_run_platform_recovery
      SET status='refunded',latest_evidence_hash=${attested.evidenceHash},updated_at=${now.toISOString()}
      WHERE action_id=${input.actionId} AND status IN ('recovering','recovered','unknown','exhausted') RETURNING action_id`);
    if (recoveryFinalized.length !== 1) {
      throw new HttpError(409, 'PLATFORM_RECOVERY_STATE_CONFLICT', 'The persisted recovery state changed before refund settlement');
    }
    const runFinalized = await query<{ id: string }>(tx, sql`UPDATE oid_benchmark_run SET status='failed',terminal_reason='platform_failure_recovery_exhausted'
      WHERE id=${run.id} AND status IN ('cancelled','unknown') AND cancellation_reason='coordinator_platform_failure'
        AND cancellation_evidence_hash IS NOT NULL RETURNING id`);
    if (runFinalized.length !== 1) {
      throw new HttpError(409, 'PLATFORM_FAILURE_STATE_CONFLICT', 'The run state changed before refund settlement');
    }
    await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata,created_at)
      VALUES (${randomUUID()},'run_platform_failure_refunded',${refundOperationId},${ownerId},${ownerId},
        ${JSON.stringify({ runId: run.id, evidenceHash: attested.evidenceHash, bonusRefundedUnits: bonusRefunded.toString(),
          originalActionId: input.actionId, originalOperationId: attested.operationId })}::jsonb,${now.toISOString()})`);
    await appendEvent(tx, run.id, 'run.failed.platform_recovery_exhausted', {
      actionId: input.actionId, operationId: attested.operationId, evidenceHash: attested.evidenceHash,
      bonusRefundedUnits: bonusRefunded.toString(), refundedSources: reservations.length, cashRefundedUnits: '0',
    }, now);
    return { runId: run.id, status: 'failed', bonusRefundedUnits: bonusRefunded.toString(), replayed: false };
  });
}
