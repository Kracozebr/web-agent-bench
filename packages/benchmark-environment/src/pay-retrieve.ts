import { createHash, timingSafeEqual } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
const address = z.string().regex(/^0x[0-9a-f]{40}$/i);
const positiveUnits = z.string().regex(/^[1-9][0-9]{0,77}$/);

export const InspectionHandleSchema = z.object({
  kind: z.enum(['catalog', 'offer']),
  operationId: uuid,
}).strict();

export const AcceptedPaymentTermsSchema = z.object({
  scheme: z.string().min(1).max(64),
  network: z.string().min(1).max(128),
  asset: address,
  amount: positiveUnits,
  payTo: address,
  transferMethod: z.string().min(1).max(64),
}).strict();

export const PayRequestSchema = z.object({
  resourceId: z.string().min(1).max(256),
  offerId: z.string().min(1).max(128),
  readHandle: InspectionHandleSchema,
  acceptedTerms: AcceptedPaymentTermsSchema,
}).strict();

export const RetrieveQuerySchema = z.object({ operationId: uuid }).strict();

export type InspectionHandle = z.infer<typeof InspectionHandleSchema>;
export type AcceptedPaymentTerms = z.infer<typeof AcceptedPaymentTermsSchema>;
export type PayRequest = z.infer<typeof PayRequestSchema>;

export type PinnedPaymentTerms = {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  transferMethod: string;
};

/** Hash the exact JSON representation stored as an inspection operation response. */
export function responseSha256(value: unknown): string {
  return createHash('sha256').update(Buffer.from(JSON.stringify(value))).digest('hex');
}

export function sameAcceptedPaymentTerms(accepted: AcceptedPaymentTerms, pinned: PinnedPaymentTerms): boolean {
  return accepted.scheme === pinned.scheme
    && accepted.network === pinned.network
    && accepted.asset.toLowerCase() === pinned.asset.toLowerCase()
    && accepted.amount === pinned.amount
    && accepted.payTo.toLowerCase() === pinned.payTo.toLowerCase()
    && accepted.transferMethod === pinned.transferMethod;
}

export function inspectionHandle(kind: InspectionHandle['kind'], operationId: string): InspectionHandle {
  return { kind, operationId };
}

function equalDigest(leftValue: string, rightValue: string): boolean {
  const left = Buffer.from(leftValue.trim().toLowerCase());
  const right = Buffer.from(rightValue.trim().toLowerCase());
  return left.length === 64 && right.length === 64 && left.length === right.length
    && /^[0-9a-f]{64}$/.test(left.toString('ascii')) && /^[0-9a-f]{64}$/.test(right.toString('ascii'))
    && timingSafeEqual(left, right);
}

/** Verify an accepted inspection row and both its request and exact response projection. */
export async function verifyInspectionRead(pool: pg.Pool, input: {
  operationId: string;
  envId: string;
  generationId: string;
  participantId: string;
  manifestSha256: string;
  kind: InspectionHandle['kind'];
  expectedRequestSha256: string;
  expectedResponseSha256: string;
}): Promise<boolean> {
  const result = await pool.query<{ operation_kind: string; status: string; request_sha256: string; response_sha256: string | null }>(
    `SELECT o.operation_kind,o.status,o.request_sha256,o.response_sha256
       FROM bef_operation o JOIN bef_generation g USING(env_id,generation_id)
      WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3 AND o.participant_id=$4
        AND g.participant_id=$4 AND g.status='active' AND g.expires_at>clock_timestamp()
        AND g.manifest_sha256=$5 AND o.operation_kind=$6 AND o.status='accepted'`,
    [input.operationId, input.envId, input.generationId, input.participantId, input.manifestSha256, input.kind],
  );
  const row = result.rows[0];
  return Boolean(row && row.operation_kind === input.kind && row.status === 'accepted' && row.response_sha256
    && equalDigest(row.request_sha256, input.expectedRequestSha256)
    && equalDigest(row.response_sha256, input.expectedResponseSha256));
}

export type PaidReceiptInput = {
  operationId: string;
  transactionHash: string;
  amount: string;
  asset: string;
  network: string;
  payTo: string;
};

/** A stable receipt projection with no delivery body, content hash, or content metadata. */
export function paidReceipt(input: PaidReceiptInput): Record<string, unknown> {
  return {
    operationId: input.operationId,
    status: 'payment_confirmed',
    payment: {
      transactionHash: input.transactionHash.toLowerCase(),
      receiptStatus: 'success',
      amount: input.amount,
      asset: input.asset.toLowerCase(),
      network: input.network,
      payTo: input.payTo.toLowerCase(),
    },
    deliveryHandle: input.operationId,
  };
}
