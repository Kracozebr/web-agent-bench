import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { sha256CanonicalTaskJson } from './task-release.js';

type Transaction = Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const Terms = z.object({ scheme: identifier, network: z.string().min(1).max(128),
  asset: z.string().regex(/^0x[0-9a-f]{40}$/i), amount: z.string().regex(/^[1-9][0-9]{0,77}$/),
  payTo: z.string().regex(/^0x[0-9a-f]{40}$/i), transferMethod: identifier }).strict();
const ReadHandle = z.object({ kind: z.enum(['offer', 'catalog']), operationId: z.string().uuid() }).strict();
export type SplitPaymentCommand = { kind: 'pay'; resourceId: string; offerId: string; offerReadActionId: string } |
  { kind: 'retrieve'; payActionId: string };
export type TaskPaymentReference = { kind: 'pay'; readHandle: z.infer<typeof ReadHandle>;
  acceptedTerms: z.infer<typeof Terms> } | { kind: 'retrieve'; operationId: string };

function reject(code: string, message: string): never { throw new HttpError(409, code, message); }
function record(value: unknown): Record<string, unknown> | null {
  if (typeof value === 'string') { try { value = JSON.parse(value) as unknown; } catch { return null; } }
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** Resolve only an already observed action of the same immutable run/task scope. */
export async function resolveTaskPaymentReference(tx: Transaction, target: {
  runId: string; taskIndex: number; environmentId: string; command: SplitPaymentCommand;
}): Promise<TaskPaymentReference> {
  const sourceId = target.command.kind === 'pay' ? target.command.offerReadActionId : target.command.payActionId;
  const rows = await tx.execute(sql`SELECT a.action_kind,a.command_json,r.receipt_status,r.tool_response_json,r.tool_response_hash,
      r.transaction_hash FROM oid_run_task_action a
    JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    JOIN oid_benchmark_run b ON b.id=a.run_id AND b.owner_id=a.owner_id AND b.agent_id=a.agent_id
      AND b.access_generation=a.access_generation
    WHERE a.id=${sourceId} AND a.run_id=${target.runId} AND a.task_index=${target.taskIndex}
      AND a.environment_id=${target.environmentId}`) as unknown as Array<{
        action_kind: string; command_json: unknown; receipt_status: string; tool_response_json: unknown;
        tool_response_hash: string | null; transaction_hash: string | null;
      }>;
  const row = rows[0], body = record(row?.tool_response_json);
  if (!row || row.receipt_status !== 'observed' || !body || !row.tool_response_hash ||
      sha256CanonicalTaskJson(body) !== row.tool_response_hash) {
    reject('TASK_PAYMENT_REFERENCE_UNAVAILABLE', 'A matching observed action with intact retained response is required');
  }
  if (target.command.kind === 'retrieve') {
    const payment = record(body.payment);
    if (row.action_kind !== 'pay' || !row.transaction_hash || body.status !== 'payment_confirmed' ||
        payment?.receiptStatus !== 'success' || typeof payment.transactionHash !== 'string' ||
        payment.transactionHash.toLowerCase() !== row.transaction_hash.toLowerCase() ||
        typeof body.operationId !== 'string' || body.deliveryHandle !== body.operationId ||
        !z.string().uuid().safeParse(body.operationId).success) {
      reject('TASK_PAYMENT_REFERENCE_INVALID', 'Retrieval must name this task’s confirmed original payment');
    }
    return { kind: 'retrieve', operationId: body.operationId };
  }
  const command = target.command;
  const kind = row.action_kind === 'inspect_offer' ? 'offer' : row.action_kind === 'inspect_catalog' ? 'catalog' : null;
  const handle = ReadHandle.safeParse(body.readHandle);
  const sourceCommand = record(row.command_json);
  if (!kind || !handle.success || handle.data.kind !== kind || body.operationId !== handle.data.operationId ||
      body.freeInspection !== true || body.deliveryState !== 'not_delivered' ||
      (kind === 'offer' && (sourceCommand?.resourceId !== command.resourceId || body.resourceId !== command.resourceId))) {
    reject('TASK_PAYMENT_REFERENCE_INVALID', 'Payment must name this task’s inspected offer or catalog');
  }
  const resources = kind === 'offer' ? [body] : Array.isArray(body.catalog) ? body.catalog.map(record) : [];
  const matching = resources.filter((value) => value?.resourceId === command.resourceId);
  if (matching.length !== 1 || !Array.isArray(matching[0]?.offers)) {
    reject('TASK_PAYMENT_OFFER_NOT_INSPECTED', 'The selected resource was not present in the inspected response');
  }
  const offers = (matching[0]!.offers as unknown[]).map(record).filter((value) => value?.id === command.offerId);
  const terms = offers.length === 1 ? Terms.safeParse(offers[0]?.payment) : null;
  if (!terms?.success) reject('TASK_PAYMENT_OFFER_NOT_INSPECTED', 'The selected offer and exact terms must be present in the inspected response');
  return { kind: 'pay', readHandle: handle.data, acceptedTerms: terms.data };
}

export async function assertTaskPaymentProtocol(tx: Transaction, runId: string,
  command: { kind: string }): Promise<void> {
  if (!['purchase', 'pay', 'retrieve'].includes(command.kind)) return;
  const rows = await tx.execute(sql`SELECT s.sealed_manifest->>'participantToolProtocol' AS protocol
    FROM oid_benchmark_run b JOIN oid_task_release s ON s.release_identity=b.release_identity AND s.manifest_hash=b.manifest_hash
    WHERE b.id=${runId}`) as unknown as Array<{ protocol: string | null }>;
  const split = rows[0]?.protocol === 'separate_payment_delivery_v2';
  if (split && command.kind === 'purchase') {
    reject('COMBINED_PURCHASE_UNAVAILABLE', 'This release uses separate payment and retrieval actions');
  }
  if (!split && (command.kind === 'pay' || command.kind === 'retrieve')) {
    reject('TASK_PAYMENT_PROTOCOL_UNAVAILABLE', 'The admitted sealed release does not enable separate payment and retrieval');
  }
}
