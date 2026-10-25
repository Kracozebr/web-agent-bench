/**
 * SC-008 read-only DB driver. It binds one operation to generation,
 * payment, selected execution, and its durable cost row in one read-only
 * snapshot. The caller must separately capture original local RPC evidence.
 */
import pg from 'pg';
import type { PoolClient } from 'pg';
import type { ProbeContext } from './runner.js';

const { Pool } = pg;

export async function observeSc008CostOperation(
  ctx: ProbeContext,
  identity: { envId: string; generationId: string; operationId: string },
  variantId: string,
  label: string,
): Promise<Record<string, unknown>> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-sc008-cost-observer',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const ro = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    if (ro.rows[0]?.transaction_read_only !== 'on' || role.rows[0]?.role_name !== ctx.database.databaseRole) {
      throw new Error('probe_sc008_database_not_readonly');
    }
    const [operation, generation, payment, selectedExecution, cost] = await Promise.all([
      client.query(
        `SELECT operation_id::text,env_id,generation_id::text,status,receipt_status,transaction_hash
           FROM bef_operation
          WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid`,
        [identity.envId, identity.generationId, identity.operationId],
      ),
      client.query(
        `SELECT env_id,generation_id::text,payer_address
           FROM bef_generation WHERE env_id=$1 AND generation_id=$2`,
        [identity.envId, identity.generationId],
      ),
      client.query(
        `SELECT operation_id::text,env_id,generation_id::text,payer_address,network,asset_address,
                amount_units::text,facilitator_address,transaction_hash
           FROM bef_payment
          WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid`,
        [identity.envId, identity.generationId, identity.operationId],
      ),
      client.query(
        `SELECT operation_id::text,env_id,generation_id::text,action_kind,selected_action_json,
                transaction_intent_json,transaction_hash,outcome,measurement_json
           FROM bef_selected_execution
          WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid`,
        [identity.envId, identity.generationId, identity.operationId],
      ),
      client.query(
        `SELECT operation_id::text,env_id,generation_id::text,transaction_hash,payer_address,payer_role,
                receipt_status,transaction_from,receipt_from,receipt_block_number::text,
                receipt_block_hash,receipt_block_parent_hash,block_transaction_senders,
                gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,
                modeled_gas_fee_usdc_units::text,fee_rate_numerator::text,fee_rate_denominator::text,
                fee_policy_snapshot,manifest_sha256,selected_principal_asset,
                selected_principal_units::text,observed_principal_units::text,
                payer_native_balance_before_wei::text,payer_native_balance_before_block_number::text,
                payer_native_balance_before_block_hash,payer_native_balance_after_wei::text,
                payer_native_balance_after_block_number::text,payer_native_balance_after_block_hash,
                receipt_evidence_json,receipt_evidence_sha256,base_l1_fee_status
           FROM bef_transaction_cost
          WHERE env_id=$1 AND generation_id=$2 AND operation_id=$3::uuid
          ORDER BY created_at,transaction_hash`,
        [identity.envId, identity.generationId, identity.operationId],
      ),
    ]);
    const payload = {
      schemaVersion: 'bef-db-observation/v1',
      boundary: 'readonly-database',
      queryName: 'sc008-cost-operation-proof',
      operationId: identity.operationId,
      variantId,
      envId: identity.envId,
      generationId: identity.generationId,
      readOnly: true,
      databaseRole: role.rows[0]!.role_name,
      transactionReadOnly: ro.rows[0]!.transaction_read_only,
      rows: {
        operation: operation.rows,
        generation: generation.rows,
        payment: payment.rows,
        selectedExecution: selectedExecution.rows,
        cost: cost.rows,
      },
    };
    await ctx.evidence.writeObservation(`db/${identity.operationId}-${label}-sc008-cost.json`, label, payload);
    await client.query('ROLLBACK');
    return payload;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message === 'probe_sc008_database_not_readonly') throw error;
    throw new Error('probe_sc008_cost_database_observation_unavailable');
  } finally {
    client.release();
    await pool.end();
  }
}

/**
 * Read-only proof that an invalid request keyed by its hashed idempotency value
 * created neither a durable operation nor any transaction-cost row.
 */
export async function observeSc008PreexecutionRejection(
  ctx: ProbeContext,
  input: { envId: string; generationId: string; idempotencyKeySha256: string; variantId: string; label: string },
): Promise<Record<string, unknown>> {
  if (!/^[0-9a-f]{64}$/i.test(input.idempotencyKeySha256)) {
    throw new Error('probe_sc008_rejection_idempotency_hash_invalid');
  }
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-sc008-cost-observer',
  });
  let client: PoolClient | null = null;
  try {
    client = await pool.connect();
    await client.query('BEGIN READ ONLY');
    const ro = await client.query<{ transaction_read_only: string }>('SHOW transaction_read_only');
    const role = await client.query<{ role_name: string }>('SELECT current_user AS role_name');
    if (ro.rows[0]?.transaction_read_only !== 'on' || role.rows[0]?.role_name !== ctx.database.databaseRole) {
      throw new Error('probe_sc008_database_not_readonly');
    }
    const result = await client.query(
      `SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.idempotency_key_sha256,
              o.status,o.receipt_status,o.transaction_hash,o.request_sha256,
              c.transaction_hash AS cost_transaction_hash,c.receipt_status AS cost_receipt_status
         FROM bef_operation o
         LEFT JOIN bef_transaction_cost c
           ON c.operation_id=o.operation_id AND c.env_id=o.env_id AND c.generation_id=o.generation_id
        WHERE o.env_id=$1 AND o.generation_id=$2 AND o.idempotency_key_sha256=$3
        ORDER BY o.operation_id,c.transaction_hash`,
      [input.envId, input.generationId, input.idempotencyKeySha256.toLowerCase()],
    );
    const operationRows = result.rows.map((row) => ({
      operation_id: row.operation_id, env_id: row.env_id, generation_id: row.generation_id,
      idempotency_key_sha256: row.idempotency_key_sha256, status: row.status,
      receipt_status: row.receipt_status, transaction_hash: row.transaction_hash,
      request_sha256: row.request_sha256,
    }));
    const costRows = result.rows.filter((row) => row.cost_transaction_hash !== null).map((row) => ({
      operation_id: row.operation_id, transaction_hash: row.cost_transaction_hash,
      receipt_status: row.cost_receipt_status,
    }));
    const payload = {
      schemaVersion: 'bef-db-observation/v1',
      boundary: 'readonly-database',
      queryName: 'sc008-preexecution-rejection-cost-proof',
      operationId: operationRows.length === 1 ? operationRows[0]!.operation_id : null,
      variantId: input.variantId,
      envId: input.envId,
      generationId: input.generationId,
      idempotencyKeySha256: input.idempotencyKeySha256.toLowerCase(),
      readOnly: true,
      databaseRole: role.rows[0]!.role_name,
      transactionReadOnly: ro.rows[0]!.transaction_read_only,
      rows: { operation: operationRows, cost: costRows },
    };
    await ctx.evidence.writeObservation(`db/${input.generationId}-${input.label}-sc008-rejection-cost.json`, input.label, payload);
    await client.query('ROLLBACK');
    return payload;
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message === 'probe_sc008_database_not_readonly') throw error;
    throw new Error('probe_sc008_rejection_cost_observation_unavailable');
  } finally {
    client?.release();
    await pool.end();
  }
}
