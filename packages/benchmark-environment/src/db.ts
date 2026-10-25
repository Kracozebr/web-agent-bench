import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import pg, { type PoolClient } from 'pg';

const { Pool } = pg;
export const poolFor = (connectionString: string) => new Pool({
  connectionString,
  max: 12,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
  statement_timeout: 5_000,
  query_timeout: 8_000,
  application_name: 'web-agent-bench-bef',
});

export const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

export type MigrationFile = { id: string; filename: string; bytes: Buffer; sql: string; sha256: string };

export async function readMigrationFiles(): Promise<MigrationFile[]> {
  const { readFile, readdir } = await import('node:fs/promises');
  const { resolve } = await import('node:path');
  const directory = resolve(process.cwd(), 'infrastructure/benchmark-environment/migrations');
  const entries = await readdir(directory, { withFileTypes: true });
  const names = entries.filter((entry) => entry.isFile() && /^\d{3}_[a-z0-9_]+\.sql$/.test(entry.name))
    .map((entry) => entry.name).sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  if (!names.length || names.some((name, index) => Number(name.slice(0, 3)) !== index + 1)) {
    throw new Error('BEF migration sequence is incomplete or ambiguous');
  }
  const result: MigrationFile[] = [];
  for (const filename of names) {
    const bytes = await readFile(resolve(directory, filename));
    result.push({ id: filename.slice(0, 3), filename, bytes, sql: bytes.toString('utf8'), sha256: sha256(bytes) });
  }
  return result;
}

export function migrationBody(sql: string): string {
  const wrapped = /^\s*BEGIN;\s*([\s\S]*?)\s*COMMIT;\s*$/i.exec(sql);
  if (!wrapped) throw new Error('BEF migration must have one outer transaction wrapper');
  return wrapped[1]!;
}

export async function applyMigration(pool: pg.Pool, migration: MigrationFile): Promise<void> {
  if (!/^\d{3}$/.test(migration.id) ||
      !new RegExp(`^${migration.id}_[a-z0-9_]+\\.sql$`).test(migration.filename) ||
      migration.bytes.toString('utf8') !== migration.sql || sha256(migration.bytes) !== migration.sha256) {
    throw new Error('BEF migration source identity is invalid');
  }
  await withTransaction(pool, async (client) => {
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('bef-schema-migrations'))`);
    const applied = await client.query<{ filename: string; sha256: string }>(
      'SELECT filename,sha256 FROM bef_schema_migration WHERE migration_id=$1', [migration.id],
    );
    const current = applied.rows[0];
    if (current) {
      if (current.filename !== migration.filename || current.sha256.trim() !== migration.sha256) {
        throw new Error(`BEF migration checksum mismatch: ${migration.filename}`);
      }
      return;
    }
    await client.query(migrationBody(migration.sql));
    await client.query(
      'INSERT INTO bef_schema_migration(migration_id,filename,sha256) VALUES ($1,$2,$3)',
      [migration.id, migration.filename, migration.sha256],
    );
  });
}

export async function ensureSchema(pool: pg.Pool): Promise<void> {
  await pool.query(`CREATE TABLE IF NOT EXISTS bef_schema_migration (
    migration_id text PRIMARY KEY CHECK (migration_id ~ '^[0-9]{3}$'),
    filename text NOT NULL UNIQUE,
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`);
  for (const migration of await readMigrationFiles()) await applyMigration(pool, migration);
}

export async function verifySchema(pool: pg.Pool): Promise<void> {
  const expected = await readMigrationFiles();
  const applied = await pool.query<{ migration_id: string; filename: string; sha256: string }>(
    'SELECT migration_id,filename,sha256 FROM bef_schema_migration ORDER BY migration_id',
  );
  if (applied.rowCount !== expected.length) throw new Error('BEF PostgreSQL migrations are not current');
  for (const [index, migration] of expected.entries()) {
    const row = applied.rows[index];
    if (!row || row.migration_id !== migration.id || row.filename !== migration.filename || row.sha256.trim() !== migration.sha256) {
      throw new Error('BEF PostgreSQL migration identity or checksum mismatch');
    }
  }
}

function sqlLiteral(value: string): string {
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(value)) throw new Error('Database role secret must be a generated URL-safe value');
  return `'${value}'`;
}

export async function setupRuntimeRoles(pool: pg.Pool, apiPassword: string, observerPassword: string): Promise<void> {
  const roles = [
    { name: 'bef_api', password: sqlLiteral(apiPassword), grants: 'SELECT, INSERT, UPDATE, DELETE' },
    { name: 'bef_observer', password: sqlLiteral(observerPassword), grants: 'SELECT' },
  ] as const;
  for (const role of roles) {
    const exists = await pool.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role.name]);
    if (exists.rowCount) {
      await pool.query(`ALTER ROLE ${role.name} WITH LOGIN PASSWORD ${role.password} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`);
    } else {
      await pool.query(`CREATE ROLE ${role.name} WITH LOGIN PASSWORD ${role.password} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`);
    }
    await pool.query(`REVOKE CREATE ON SCHEMA public FROM ${role.name}`);
    await pool.query(`GRANT USAGE ON SCHEMA public TO ${role.name}`);
    await pool.query(`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${role.name}`);
    await pool.query(`GRANT ${role.grants} ON ALL TABLES IN SCHEMA public TO ${role.name}`);
    await pool.query(`REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${role.name}`);
    if (role.name === 'bef_api') await pool.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${role.name}`);
    if (role.name === 'bef_api') {
      await pool.query(`REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE bef_selected_execution_event FROM ${role.name}`);
      await pool.query(`REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE bef_schema_migration FROM ${role.name}`);
    }
  }
  await pool.query('ALTER DEFAULT PRIVILEGES FOR ROLE bef_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bef_api');
  await pool.query('ALTER DEFAULT PRIVILEGES FOR ROLE bef_owner IN SCHEMA public GRANT SELECT ON TABLES TO bef_observer');
  await pool.query('ALTER DEFAULT PRIVILEGES FOR ROLE bef_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO bef_api');
}

export async function withTransaction<T>(pool: pg.Pool, callback: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

const ENVIRONMENT_LOCK_WAIT_MS = 2_000;
const ENVIRONMENT_LOCK_RETRY_MS = 25;

export class EnvironmentAdvisoryLockTimeout extends Error {
  constructor() {
    super('environment_advisory_lock_timeout');
    this.name = 'EnvironmentAdvisoryLockTimeout';
  }
}

async function connectBeforeDeadline(pool: pg.Pool, deadline: number): Promise<PoolClient> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pendingClient = pool.connect().then((client) => {
    if (performance.now() >= deadline) {
      client.release();
      throw new EnvironmentAdvisoryLockTimeout();
    }
    return client;
  });
  try {
    return await Promise.race([
      pendingClient,
      new Promise<PoolClient>((_resolve, reject) => {
        timer = setTimeout(() => reject(new EnvironmentAdvisoryLockTimeout()), Math.max(0, deadline - performance.now()));
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function withEnvironmentAdvisoryLock<T>(pool: pg.Pool, envId: string, callback: () => Promise<T>, maxWaitMs = ENVIRONMENT_LOCK_WAIT_MS): Promise<T> {
  if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs < 0) throw new Error('invalid_environment_lock_wait');
  const deadline = performance.now() + maxWaitMs;
  while (true) {
    const client = await connectBeforeDeadline(pool, deadline);
    let locked = false;
    let discarded = false;
    try {
      const remainingMs = Math.max(1, deadline - performance.now());
      let attempt: pg.QueryResult<{ acquired: boolean }>;
      try {
        const pendingAttempt = client.query<{ acquired: boolean }>(
          "SELECT pg_try_advisory_lock(hashtext('bef-runtime-environment'), hashtext($1)) AS acquired",
          [envId],
        );
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<pg.QueryResult<{ acquired: boolean }>>((_resolve, reject) => {
          timer = setTimeout(() => reject(new EnvironmentAdvisoryLockTimeout()), Math.max(0, deadline - performance.now()));
        });
        pendingAttempt.then(() => { if (timer) clearTimeout(timer); }, () => { if (timer) clearTimeout(timer); });
        attempt = await Promise.race([pendingAttempt, timeout]);
      } catch (error) {
        // A timed out query may have acquired the session lock without returning its result.
        // Destroying this connection releases any such lock on the server.
        client.release(error instanceof Error ? error : new Error('environment_lock_result_unknown'));
        discarded = true;
        throw error;
      }
      locked = attempt.rows[0]?.acquired === true;
      if (locked && performance.now() < deadline) return await callback();
    } finally {
      if (!discarded) {
        if (locked) {
          try {
            const unlock = await client.query<{ released: boolean }>("SELECT pg_advisory_unlock(hashtext('bef-runtime-environment'), hashtext($1)) AS released", [envId]);
            if (unlock.rows[0]?.released !== true) throw new Error('environment_advisory_unlock_failed');
          } catch {
            client.release(new Error('environment_advisory_unlock_failed'));
            discarded = true;
            throw new Error('environment_advisory_unlock_failed');
          }
        }
        if (!discarded) client.release();
      }
    }
    const remainingMs = deadline - performance.now();
    if (remainingMs <= 0) throw new EnvironmentAdvisoryLockTimeout();
    await new Promise<void>((resolve) => setTimeout(resolve, Math.min(ENVIRONMENT_LOCK_RETRY_MS, remainingMs)));
  }
}

export async function registerManifest(pool: pg.Pool, envId: string, manifestSha256: string): Promise<void> {
  await pool.query(
    `INSERT INTO bef_environment(env_id, chain_id, node_identity, manifest_sha256)
     VALUES ($1, 8453, 'private-anvil-fork', $2)
     ON CONFLICT (env_id) DO UPDATE SET chain_id = EXCLUDED.chain_id, node_identity = EXCLUDED.node_identity, manifest_sha256 = EXCLUDED.manifest_sha256`,
    [envId, manifestSha256],
  );
}

export async function insertOperation(pool: pg.Pool, input: {
  envId: string;
  generationId: string;
  participantId: string;
  idempotencyKey: string;
  requestHash: string;
  kind: string;
}): Promise<{ operationId: string; status: string; requestHash: string; isNew: boolean }> {
  const operationId = randomUUID();
  const result = await pool.query(
    `INSERT INTO bef_operation(operation_id, env_id, generation_id, participant_id, idempotency_key_sha256, request_sha256, operation_kind, status, offer_selection_eligible)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'awaiting_payment', $8)
     ON CONFLICT (env_id, generation_id, participant_id, idempotency_key_sha256) DO NOTHING
     RETURNING operation_id, status, request_sha256`,
    [operationId, input.envId, input.generationId, input.participantId, sha256(input.idempotencyKey), input.requestHash, input.kind, input.kind === 'purchase'],
  );
  if (result.rowCount) return { operationId, status: result.rows[0].status as string, requestHash: result.rows[0].request_sha256 as string, isNew: true };
  const existing = await pool.query(
    `SELECT operation_id, status, request_sha256 FROM bef_operation
     WHERE env_id=$1 AND generation_id=$2 AND participant_id=$3 AND idempotency_key_sha256=$4`,
    [input.envId, input.generationId, input.participantId, sha256(input.idempotencyKey)],
  );
  const row = existing.rows[0] as { operation_id: string; status: string; request_sha256: string } | undefined;
  if (!row) throw new Error('Idempotency operation disappeared during concurrent lookup');
  return { operationId: row.operation_id, status: row.status, requestHash: row.request_sha256, isNew: false };
}

export const runTokenHash = (token: string) => sha256(token);
