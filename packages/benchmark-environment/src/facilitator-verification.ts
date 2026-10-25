import type pg from 'pg';
import { withEnvironmentAdvisoryLock, withTransaction } from './db.js';

export type PrivateVerificationBinding = {
  envId: string;
  generationId: string;
  operationId: string;
  requestSha256: string;
};

export type PinnedVerificationOffer = { id: string; amount: string };

/** Record verification for the no-receipt fixture without making it look like settlement is pending. */
export async function recordPrivateVerificationStarted(
  pool: pg.Pool,
  binding: PrivateVerificationBinding,
  offer: PinnedVerificationOffer,
): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(binding.requestSha256)) return false;
  return withEnvironmentAdvisoryLock(pool, binding.envId, () => withTransaction(pool, async (client) => {
    const current = await client.query<{
      resource_variant: string;
      request_sha256: string;
      operation_kind: string;
      status: string;
      selected_offer_id: string | null;
      selected_amount_units: string | null;
      offer_selected_at: Date | string | null;
      verification_started_at: Date | string | null;
      offer_selection_eligible: boolean;
      selection_precedes_verification: boolean;
    }>(
      `SELECT g.resource_variant,o.request_sha256,o.operation_kind,o.status,o.selected_offer_id,
              o.selected_amount_units::text,o.offer_selected_at,o.verification_started_at,
              o.offer_selection_eligible,
              (o.offer_selected_at IS NOT NULL AND o.verification_started_at IS NOT NULL
                AND o.verification_started_at >= o.offer_selected_at) AS selection_precedes_verification
         FROM bef_generation g
         JOIN bef_operation o ON o.env_id=g.env_id AND o.generation_id=g.generation_id
        WHERE g.env_id=$1 AND g.generation_id=$2 AND g.status='active'
          AND g.expires_at>clock_timestamp() AND g.resource_variant='verification_without_receipt'
          AND o.operation_id=$3 AND o.request_sha256=$4
        FOR UPDATE OF g,o`,
      [binding.envId, binding.generationId, binding.operationId, binding.requestSha256],
    );
    const row = current.rows[0];
    if (!row || row.resource_variant !== 'verification_without_receipt'
      || row.request_sha256.trim().toLowerCase() !== binding.requestSha256
      || row.operation_kind !== 'purchase' || row.status !== 'awaiting_payment'
      || row.selected_offer_id !== offer.id || row.selected_amount_units !== offer.amount
      || row.offer_selected_at === null || row.offer_selection_eligible !== false) return false;
    if (row.verification_started_at !== null) return row.selection_precedes_verification === true;

    const updated = await client.query(
      `UPDATE bef_operation o SET verification_started_at=clock_timestamp()
        WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3 AND o.request_sha256=$4
          AND o.operation_kind='purchase' AND o.status='awaiting_payment'
          AND o.selected_offer_id=$5 AND o.selected_amount_units=$6
          AND o.offer_selected_at IS NOT NULL AND o.offer_selection_eligible=false
          AND o.verification_started_at IS NULL
          AND EXISTS (
            SELECT 1 FROM bef_generation g
             WHERE g.env_id=o.env_id AND g.generation_id=o.generation_id
               AND g.status='active' AND g.expires_at>clock_timestamp()
               AND g.resource_variant='verification_without_receipt'
          )
        RETURNING o.operation_id`,
      [binding.operationId, binding.envId, binding.generationId, binding.requestSha256, offer.id, offer.amount],
    );
    return updated.rowCount === 1;
  }));
}
