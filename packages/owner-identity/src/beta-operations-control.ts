import { randomUUID, createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';

const OPERATION_ID = /^[A-Za-z0-9_-]{12,128}$/;
const HASH = /^[0-9a-f]{64}$/;
const REASONS = ['maintenance', 'incident_response', 'resource_pressure', 'scheduled_pause', 'other'] as const;
export type BetaOperationsMode = 'active' | 'paused';
export type BetaOperationsReason = (typeof REASONS)[number];
type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];

type ControlRow = {
  mode: BetaOperationsMode;
  revision: string | bigint | number;
  changed_at: Date | string;
  changed_by_owner_id: string | null;
  reason_code: BetaOperationsReason | null;
  operation_id: string | null;
};

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('PostgreSQL returned an unexpected operations-control result');
  return value as T[];
}

async function query<T>(tx: Transaction, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await tx.execute(statement));
}

function revisionNumber(value: string | bigint | number): number {
  const revision = Number(value);
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new HttpError(503, 'OPERATIONS_CONTROL_INVALID', 'The persisted operations-control revision is invalid');
  }
  return revision;
}

function parseControl(row: ControlRow | undefined) {
  if (!row || !['active', 'paused'].includes(row.mode) ||
      (row.reason_code !== null && !REASONS.includes(row.reason_code))) {
    throw new HttpError(503, 'OPERATIONS_CONTROL_UNAVAILABLE', 'The persisted operations-control state is unavailable');
  }
  const changedAt = row.changed_at instanceof Date ? row.changed_at : new Date(row.changed_at);
  if (!Number.isFinite(changedAt.getTime())) {
    throw new HttpError(503, 'OPERATIONS_CONTROL_INVALID', 'The persisted operations-control timestamp is invalid');
  }
  return { mode: row.mode, revision: revisionNumber(row.revision), changedAt: changedAt.toISOString(),
    changedByOwnerId: row.changed_by_owner_id, reasonCode: row.reason_code, operationId: row.operation_id };
}

export const betaOperationsControlMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_beta_operations_control (
    id smallint PRIMARY KEY CHECK(id=1),
    mode text NOT NULL CHECK(mode IN ('active','paused')),
    revision bigint NOT NULL DEFAULT 0 CHECK(revision >= 0),
    changed_at timestamptz NOT NULL DEFAULT now(),
    changed_by_owner_id uuid REFERENCES oid_owner(id) ON DELETE RESTRICT,
    reason_code text CHECK(reason_code IS NULL OR reason_code IN ('maintenance','incident_response','resource_pressure','scheduled_pause','other')),
    operation_id text CHECK(operation_id IS NULL OR operation_id ~ '^[A-Za-z0-9_-]{12,128}$')
  )`,
  `INSERT INTO oid_beta_operations_control(id,mode,revision) VALUES (1,'active',0) ON CONFLICT (id) DO NOTHING`,
  `CREATE TABLE IF NOT EXISTS oid_beta_operations_control_event (
    id uuid PRIMARY KEY,
    operation_id text NOT NULL UNIQUE CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    actor_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    revision bigint NOT NULL UNIQUE CHECK(revision > 0),
    previous_mode text NOT NULL CHECK(previous_mode IN ('active','paused')),
    next_mode text NOT NULL CHECK(next_mode IN ('active','paused')),
    reason_code text NOT NULL CHECK(reason_code IN ('maintenance','incident_response','resource_pressure','scheduled_pause','other')),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS oid_beta_operations_control_event_actor_created_idx
    ON oid_beta_operations_control_event(actor_owner_id,created_at DESC)`,
  `CREATE OR REPLACE FUNCTION oid_reject_beta_operations_control_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'beta operations control events are append-only' USING ERRCODE='55000'; END; $$`,
  `DROP TRIGGER IF EXISTS oid_beta_operations_control_event_immutable_trg ON oid_beta_operations_control_event`,
  `CREATE TRIGGER oid_beta_operations_control_event_immutable_trg BEFORE UPDATE OR DELETE ON oid_beta_operations_control_event
    FOR EACH ROW EXECUTE FUNCTION oid_reject_beta_operations_control_event_mutation()`,
];

export async function migrateBetaOperationsControl(tx: { unsafe(query: string): Promise<unknown> }): Promise<void> {
  for (const statement of betaOperationsControlMigrationStatements) await tx.unsafe(statement);
}

export async function lockBetaRunStartControl(tx: Transaction): Promise<BetaOperationsMode> {
  const found = await query<{ mode: string }>(tx, sql`SELECT mode FROM oid_beta_operations_control WHERE id=1 FOR SHARE`);
  const mode = found[0]?.mode;
  if (mode !== 'active' && mode !== 'paused') {
    throw new HttpError(503, 'OPERATIONS_CONTROL_UNAVAILABLE', 'The persisted operations-control state is unavailable');
  }
  if (mode === 'paused') {
    throw new HttpError(423, 'BETA_STARTS_PAUSED', 'New benchmark starts are paused by the administrator');
  }
  return mode;
}

export async function readBetaOperationsMode(db: OwnerDatabase): Promise<BetaOperationsMode> {
  const found = rows<{ mode: string }>(await db.execute(sql`SELECT mode FROM oid_beta_operations_control WHERE id=1`));
  const mode = found[0]?.mode;
  if (mode !== 'active' && mode !== 'paused') {
    throw new HttpError(503, 'OPERATIONS_CONTROL_UNAVAILABLE', 'The persisted operations-control state is unavailable');
  }
  return mode;
}

export async function readBetaOperationsControl(db: OwnerDatabase) {
  const found = rows<ControlRow>(await db.execute(sql`SELECT mode,revision::text,changed_at,changed_by_owner_id,reason_code,operation_id
    FROM oid_beta_operations_control WHERE id=1`));
  return parseControl(found[0]);
}

export async function listBetaOperationsControlEvents(db: OwnerDatabase, limit = 20) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('Invalid operations-control event limit');
  const found = rows<{ operation_id: string; actor_owner_id: string; revision: string | bigint | number;
    previous_mode: BetaOperationsMode; next_mode: BetaOperationsMode; reason_code: BetaOperationsReason; created_at: Date | string }>(
    await db.execute(sql`SELECT operation_id,actor_owner_id,revision::text,previous_mode,next_mode,reason_code,created_at
      FROM oid_beta_operations_control_event ORDER BY revision DESC LIMIT ${limit}`));
  return found.map((event) => {
    const createdAt = event.created_at instanceof Date ? event.created_at : new Date(event.created_at);
    return { operationId: event.operation_id, actorOwnerId: event.actor_owner_id, revision: revisionNumber(event.revision),
      previousMode: event.previous_mode, mode: event.next_mode, reasonCode: event.reason_code,
      createdAt: Number.isFinite(createdAt.getTime()) ? createdAt.toISOString() : null };
  });
}

export async function updateBetaOperationsControl(db: OwnerDatabase, input: {
  actorOwnerId: string; operationId: string; expectedRevision: number; mode: BetaOperationsMode; reasonCode: BetaOperationsReason;
}): Promise<{ control: ReturnType<typeof parseControl>; replayed: boolean }> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.actorOwnerId) ||
      !OPERATION_ID.test(input.operationId) || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0 ||
      !['active', 'paused'].includes(input.mode) || !REASONS.includes(input.reasonCode)) {
    throw new HttpError(400, 'INVALID_OPERATIONS_CONTROL', 'The operations-control update is malformed');
  }
  const payloadHash = createHash('sha256').update(JSON.stringify({ expectedRevision: input.expectedRevision,
    mode: input.mode, reasonCode: input.reasonCode })).digest('hex');

  return db.transaction(async (tx) => {
    const currentRows = await query<ControlRow>(tx, sql`SELECT mode,revision::text,changed_at,changed_by_owner_id,reason_code,operation_id
      FROM oid_beta_operations_control WHERE id=1 FOR UPDATE`);
    const current = parseControl(currentRows[0]);
    const priorRows = await query<{ actor_owner_id: string; payload_hash: string; revision: string | bigint | number }>(tx,
      sql`SELECT actor_owner_id,payload_hash,revision::text FROM oid_beta_operations_control_event WHERE operation_id=${input.operationId}`);
    const prior = priorRows[0];
    if (prior) {
      if (prior.actor_owner_id !== input.actorOwnerId || prior.payload_hash !== payloadHash) {
        throw new HttpError(409, 'OPERATIONS_CONTROL_IDEMPOTENCY_CONFLICT', 'The operation ID is already bound to a different administrator update');
      }
      return { control: current, replayed: true };
    }
    if (current.revision !== input.expectedRevision) {
      throw new HttpError(409, 'OPERATIONS_CONTROL_REVISION_CONFLICT', 'The operations-control revision changed; refresh before retrying');
    }

    const nextRevision = current.revision + 1;
    const nowRows = await query<{ now: Date | string }>(tx, sql`SELECT clock_timestamp() AS now`);
    const nowValue = nowRows[0]?.now;
    const changedAt = nowValue instanceof Date ? nowValue : new Date(String(nowValue));
    if (!Number.isFinite(changedAt.getTime())) throw new Error('PostgreSQL clock returned an invalid operations-control timestamp');
    await tx.execute(sql`UPDATE oid_beta_operations_control SET mode=${input.mode},revision=${nextRevision},changed_at=${changedAt.toISOString()},
      changed_by_owner_id=${input.actorOwnerId},reason_code=${input.reasonCode},operation_id=${input.operationId} WHERE id=1`);
    await tx.execute(sql`INSERT INTO oid_beta_operations_control_event(id,operation_id,actor_owner_id,revision,previous_mode,next_mode,
      reason_code,payload_hash,created_at) VALUES (${randomUUID()},${input.operationId},${input.actorOwnerId},${nextRevision},
      ${current.mode},${input.mode},${input.reasonCode},${payloadHash},${changedAt.toISOString()})`);
    return { control: { mode: input.mode, revision: nextRevision, changedAt: changedAt.toISOString(),
      changedByOwnerId: input.actorOwnerId, reasonCode: input.reasonCode, operationId: input.operationId }, replayed: false };
  });
}
