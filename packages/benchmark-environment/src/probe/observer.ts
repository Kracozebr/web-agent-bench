import pg from 'pg';
import { sanitizeValue, type EvidenceWriter } from './evidence.js';
import { sha256Bytes } from './evidence.js';
import type { ReplayedOriginalCaptureReference } from './types.js';

const { Pool } = pg;

export type SnapshotSelector = {
  envId: string;
  generationId: string;
  operationId?: string;
  idempotencyKey?: string;
  variantId: string | null;
  label: string;
  observationScope?: 'operation' | 'generation';
  observationOperationId?: string | null;
  generationOperationIds?: string[];
  replayPhase?: 'before' | 'after';
  replayedOriginalCapture?: ReplayedOriginalCaptureReference;
};

export function snapshotObservationIdentity(
  selector: SnapshotSelector,
  transactionReadOnly: string,
): { envId: string; generationId: string; transactionReadOnly: 'on' } {
  if (transactionReadOnly !== 'on') throw new Error('probe_database_snapshot_not_readonly');
  return {
    envId: selector.envId,
    generationId: selector.generationId,
    transactionReadOnly,
  };
}

export type SnapshotRows = {
  generation: Record<string, unknown>[];
  operations: Record<string, unknown>[];
  payments: Record<string, unknown>[];
  deliveries: Record<string, unknown>[];
  denials: Record<string, unknown>[];
  x402Observations: Record<string, unknown>[];
};

const REQUIRED_OBSERVER_TABLES = [
  'bef_environment',
  'bef_generation',
  'bef_operation',
  'bef_payment',
  'bef_x402_observation',
  'bef_delivery',
  'bef_denial',
  'bef_rpc_observation',
  'bef_evidence_artifact',
  'bef_resource_sample',
  'bef_selected_execution',
  'bef_selected_execution_event',
  'bef_transaction_cost',
] as const;

type ObserverPrivilegeProof = {
  role: Record<string, unknown>;
  tables: Array<Record<string, unknown>>;
  postgresVersion: string;
};

export class DatabaseObserver {
  private readonly pool: pg.Pool;
  private roleName = '';
  private privilegeProof: ObserverPrivilegeProof | null = null;
  private deadlineAtMs = Number.POSITIVE_INFINITY;

  constructor(connectionString: string, private readonly evidence: EvidenceWriter) {
    this.pool = new Pool({
      connectionString,
      max: 2,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 5_000,
      statement_timeout: 5_000,
      query_timeout: 8_000,
      application_name: 'web-agent-bench-bef-probe-readonly',
    });
  }

  get databaseRole(): string {
    return this.roleName;
  }

  setDeadlineAt(deadlineAtMs: number): void {
    this.deadlineAtMs = deadlineAtMs;
  }

  async verifyReadOnlyRole(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN READ ONLY');
      const state = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
      const role = await client.query<{
        role_name: string;
        is_superuser: boolean;
        can_create_db: boolean;
        can_create_role: boolean;
        can_replicate: boolean;
        can_bypass_rls: boolean;
        can_create_in_schema: boolean;
        can_create_in_database: boolean;
      }>(`SELECT current_user AS role_name, r.rolsuper AS is_superuser,
                 r.rolcreatedb AS can_create_db, r.rolcreaterole AS can_create_role,
                 r.rolreplication AS can_replicate, r.rolbypassrls AS can_bypass_rls,
                 has_schema_privilege(current_user, current_schema(), 'CREATE') AS can_create_in_schema,
                 has_database_privilege(current_user, current_database(), 'CREATE') AS can_create_in_database
          FROM pg_roles r WHERE r.rolname = current_user`);
      const flags = role.rows[0];
      const privileges = await client.query<{
        table_name: string;
        can_select: boolean;
        can_insert: boolean;
        can_update: boolean;
        can_delete: boolean;
        can_truncate: boolean;
        can_references: boolean;
        can_trigger: boolean;
      }>(`SELECT c.relname AS table_name,
                 has_table_privilege(current_user, c.oid, 'SELECT') AS can_select,
                 has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
                 has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
                 has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete,
                 has_table_privilege(current_user, c.oid, 'TRUNCATE') AS can_truncate,
                 has_table_privilege(current_user, c.oid, 'REFERENCES') AS can_references,
                 has_table_privilege(current_user, c.oid, 'TRIGGER') AS can_trigger
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND c.relname LIKE 'bef_%'
          ORDER BY c.relname`);
      const postgres = await client.query<{ version: string }>('SELECT version() AS version');
      const tableNames = new Set(privileges.rows.map((row) => row.table_name));
      const missingTables = REQUIRED_OBSERVER_TABLES.filter((table) => !tableNames.has(table));
      const hasWritePrivilege = privileges.rows.some((row) =>
        row.can_insert || row.can_update || row.can_delete || row.can_truncate || row.can_references || row.can_trigger);
      if (state.rows[0]?.transaction_read_only !== 'on' || !flags
        || flags.is_superuser || flags.can_create_db || flags.can_create_role || flags.can_replicate
        || flags.can_bypass_rls || flags.can_create_in_schema || flags.can_create_in_database
        || missingTables.length > 0 || privileges.rows.some((row) => !row.can_select) || hasWritePrivilege) {
        throw new Error('probe_database_observer_not_readonly');
      }
      this.roleName = flags.role_name;
      this.privilegeProof = {
        role: flags as unknown as Record<string, unknown>,
        tables: privileges.rows as unknown as Array<Record<string, unknown>>,
        postgresVersion: postgres.rows[0]?.version ?? 'unknown',
      };
      await client.query('ROLLBACK');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (error instanceof Error && error.message === 'probe_database_observer_not_readonly') throw error;
      throw new Error('probe_database_observer_unavailable');
    } finally {
      client.release();
    }
  }

  get observedPostgresVersion(): string {
    return this.privilegeProof?.postgresVersion ?? 'unknown';
  }

  async writePrivilegeObservation(): Promise<void> {
    if (!this.roleName || !this.privilegeProof) throw new Error('probe_database_observer_not_verified');
    await this.evidence.writeObservation('db/observer-role-privileges.json', 'observer-role-privileges', {
      schemaVersion: 'bef-db-observation/v1',
      boundary: 'readonly-database',
      operationId: null,
      variantId: null,
      readOnly: true,
      databaseRole: this.roleName,
      queryName: 'observer-role-effective-privileges',
      role: sanitizeValue(this.privilegeProof.role),
      rows: sanitizeValue(this.privilegeProof.tables),
      postgresVersion: this.privilegeProof.postgresVersion,
    });
  }

  async originalOperationGenerationBindings(input: {
    envId: string;
    operationIds: string[];
    label: string;
    replayPhase: 'before' | 'after';
    replayedOriginalCapture: ReplayedOriginalCaptureReference;
  }): Promise<Array<{ operation_id: string; env_id: string; generation_id: string }>> {
    if (!this.roleName) throw new Error('probe_database_observer_not_verified');
    if (this.deadlineAtMs - Date.now() <= 8_000) throw new Error('probe_trial_guardrail_deadline_exceeded');
    if (!input.envId || input.operationIds.length === 0
      || input.operationIds.some((id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))) {
      throw new Error('probe_sc012_original_operation_ids_invalid');
    }

    const client = await this.pool.connect();
    let rows: Array<{ operation_id: string; env_id: string; generation_id: string }>;
    try {
      await client.query('BEGIN READ ONLY');
      const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
      const mode = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
      if (role.rows[0]?.role_name !== this.roleName || mode.rows[0]?.transaction_read_only !== 'on') {
        throw new Error('probe_database_role_changed');
      }
      const result = await client.query(
        `SELECT operation_id, env_id, generation_id
         FROM bef_operation WHERE env_id=$1 AND operation_id = ANY($2::uuid[]) ORDER BY operation_id`,
        [input.envId, input.operationIds],
      );
      rows = result.rows as Array<{ operation_id: string; env_id: string; generation_id: string }>;
      await client.query('COMMIT');
    } catch {
      await client.query('ROLLBACK').catch(() => undefined);
      throw new Error('probe_sc012_original_operation_binding_read_failed');
    } finally {
      client.release();
    }

    await this.evidence.writeObservation(`db/${input.label}-operation-generation-bindings.json`, `${input.label}-operation-generation-bindings`, {
      schemaVersion: 'bef-db-observation/v1',
      boundary: 'readonly-database',
      operationId: null,
      variantId: null,
      readOnly: true,
      databaseRole: this.roleName,
      queryName: 'replayed-original-operation-generation-bindings',
      observationScope: 'original-operation-bindings',
      observationOperationId: null,
      replayPhase: input.replayPhase,
      replayedOriginalCapture: input.replayedOriginalCapture,
      envId: input.envId,
      operationIds: input.operationIds,
      rows: sanitizeValue(rows),
    });
    return rows;
  }

  async snapshot(selector: SnapshotSelector): Promise<SnapshotRows> {
    if (!this.roleName) throw new Error('probe_database_observer_not_verified');
    if (this.deadlineAtMs - Date.now() <= 8_000) throw new Error('probe_trial_guardrail_deadline_exceeded');
    const client = await this.pool.connect();
    let rows: SnapshotRows;
    let observationIdentity: ReturnType<typeof snapshotObservationIdentity>;
    try {
      await client.query('BEGIN READ ONLY');
      const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
      const mode = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
      const transactionReadOnly = mode.rows[0]?.transaction_read_only;
      if (role.rows[0]?.role_name !== this.roleName || transactionReadOnly !== 'on') {
        throw new Error('probe_database_role_changed');
      }
      observationIdentity = snapshotObservationIdentity(selector, transactionReadOnly);

      const generation = await client.query(
        `SELECT generation_id, env_id, participant_id, payer_address, status, fixture_hash, created_at, fenced_at
         FROM bef_generation WHERE env_id=$1 AND generation_id=$2`,
        [selector.envId, selector.generationId],
      );

      let operations;
      if (selector.operationId) {
        operations = await client.query(
          `SELECT operation_id, env_id, generation_id, participant_id, idempotency_key_sha256,
                  request_sha256, operation_kind, status, transaction_hash, receipt_status,
                  response_sha256, selected_offer_id, selected_amount_units, offer_selected_at,
                  verification_started_at, started_at, completed_at
           FROM bef_operation WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
          [selector.operationId, selector.envId, selector.generationId],
        );
      } else if (selector.idempotencyKey) {
        const keyHash = sha256Bytes(Buffer.from(selector.idempotencyKey, 'utf8'));
        operations = await client.query(
          `SELECT operation_id, env_id, generation_id, participant_id, idempotency_key_sha256,
                  request_sha256, operation_kind, status, transaction_hash, receipt_status,
                  response_sha256, selected_offer_id, selected_amount_units, offer_selected_at,
                  verification_started_at, started_at, completed_at
           FROM bef_operation
           WHERE env_id=$1 AND generation_id=$2 AND idempotency_key_sha256=$3`,
          [selector.envId, selector.generationId, keyHash],
        );
      } else {
        operations = await client.query(
          `SELECT operation_id, env_id, generation_id, participant_id, idempotency_key_sha256,
                  request_sha256, operation_kind, status, transaction_hash, receipt_status,
                  response_sha256, selected_offer_id, selected_amount_units, offer_selected_at,
                  verification_started_at, started_at, completed_at
           FROM bef_operation WHERE env_id=$1 AND generation_id=$2 ORDER BY started_at`,
          [selector.envId, selector.generationId],
        );
      }

      const operationIds = operations.rows.map((row: { operation_id: string }) => row.operation_id);
      let payments: pg.QueryResult;
      let deliveries: pg.QueryResult;
      let denials: pg.QueryResult;
      let x402Observations: pg.QueryResult;
      if (operationIds.length) {
        payments = await client.query(
          `SELECT payment_id, operation_id, env_id, generation_id, payer_address, network,
                  asset_address, amount_units, facilitator_address, transaction_hash,
                  receipt_status, token_delta_units, observed_at
           FROM bef_payment WHERE operation_id = ANY($1::uuid[]) ORDER BY observed_at`,
          [operationIds],
        );
        deliveries = await client.query(
          `SELECT delivery_id, operation_id, resource_id, content_sha256, content_bytes, delivered_at
           FROM bef_delivery WHERE operation_id = ANY($1::uuid[]) ORDER BY delivered_at`,
          [operationIds],
        );
        denials = await client.query(
          `SELECT denial_id, env_id, generation_id, operation_id, route, reason_code,
                  request_sha256, protected_state_sha256, created_at
           FROM bef_denial WHERE generation_id=$1 AND (operation_id = ANY($2::uuid[]) OR operation_id IS NULL)
           ORDER BY created_at`,
          [selector.generationId, operationIds],
        );
        x402Observations = await client.query(
          `SELECT observation_id, env_id, generation_id, operation_id, variant_id, phase,
                  request_sha256, safe_request, response_sha256, safe_response, outcome,
                  transaction_hash, observed_at
           FROM bef_x402_observation WHERE operation_id = ANY($1::uuid[]) ORDER BY observed_at`,
          [operationIds],
        );
      } else {
        payments = await client.query('SELECT payment_id, operation_id, env_id, generation_id, payer_address, network, asset_address, amount_units, facilitator_address, transaction_hash, receipt_status, token_delta_units, observed_at FROM bef_payment WHERE generation_id=$1 ORDER BY observed_at', [selector.generationId]);
        deliveries = await client.query('SELECT delivery_id, operation_id, resource_id, content_sha256, content_bytes, delivered_at FROM bef_delivery WHERE operation_id IN (SELECT operation_id FROM bef_operation WHERE generation_id=$1) ORDER BY delivered_at', [selector.generationId]);
        denials = await client.query('SELECT denial_id, env_id, generation_id, operation_id, route, reason_code, request_sha256, protected_state_sha256, created_at FROM bef_denial WHERE generation_id=$1 ORDER BY created_at', [selector.generationId]);
        x402Observations = await client.query(
          'SELECT observation_id, env_id, generation_id, operation_id, variant_id, phase, request_sha256, safe_request, response_sha256, safe_response, outcome, transaction_hash, observed_at FROM bef_x402_observation WHERE generation_id=$1 ORDER BY observed_at',
          [selector.generationId],
        );
      }

      await client.query('COMMIT');
      rows = {
        generation: generation.rows as Record<string, unknown>[],
        operations: operations.rows as Record<string, unknown>[],
        payments: payments.rows as Record<string, unknown>[],
        deliveries: deliveries.rows as Record<string, unknown>[],
        denials: denials.rows as Record<string, unknown>[],
        x402Observations: x402Observations.rows as Record<string, unknown>[],
      };
    } catch {
      await client.query('ROLLBACK').catch(() => undefined);
      throw new Error('probe_database_snapshot_failed');
    } finally {
      client.release();
    }

    const queryEntries: Array<[keyof SnapshotRows, string]> = [
      ['generation', 'generation-by-id'],
      ['operations', selector.operationId ? 'operation-by-id' : selector.idempotencyKey ? 'operation-by-idempotency-key-hash' : 'operations-by-generation'],
      ['payments', 'payments-by-operation'],
      ['deliveries', 'deliveries-by-operation'],
      ['denials', 'denials-by-generation'],
      ['x402Observations', 'x402-observations-by-operation'],
    ];
    for (const [key, queryName] of queryEntries) {
      await this.evidence.writeObservation(`db/${selector.label}-${queryName}.json`, `${selector.label}-${queryName}`, {
        schemaVersion: 'bef-db-observation/v1',
        boundary: 'readonly-database',
        operationId: selector.observationOperationId !== undefined
          ? selector.observationOperationId
          : selector.operationId ?? (rows.operations[0]?.operation_id as string | undefined) ?? null,
        variantId: selector.variantId,
        readOnly: true,
        databaseRole: this.roleName,
        queryName,
        ...(selector.observationScope ? {
          observationScope: selector.observationScope,
          observationOperationId: selector.observationOperationId ?? null,
        } : {}),
        ...observationIdentity,
        ...(selector.generationOperationIds ? { generationOperationIds: selector.generationOperationIds } : {}),
        ...(selector.replayPhase ? { replayPhase: selector.replayPhase } : {}),
        ...(selector.replayedOriginalCapture ? { replayedOriginalCapture: selector.replayedOriginalCapture } : {}),
        rows: sanitizeValue(rows[key]),
      });
    }
    return rows;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
