/**
 * H3 paid-reference to route-selected swap foundation.
 * This captures one isolated local-fork generation; it is not task acceptance.
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import type { RuntimeManifest } from '../manifest.js';
import { loadPinnedResources } from '../resource.js';
import { apiPath } from './environment.js';
import { sanitizeValue } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { transferEvents } from './rpc.js';
import { projectDeliveryEnvelope } from './task-reference-cases.js';
import { readCaseDatabaseFacts } from './task-reference-case-drivers.js';
import { projectPinnedPublicCatalog } from './task-reference-catalog-objectives.js';
import { projectRouteDelivery } from './task-route-reference.js';
import {
  approveUsdcInSession,
  readNativeStateInSession,
  swapUsdcToWethInSession,
  type NativeStateSnapshot,
} from './task-native-capture.js';
import { createSignedPayload, readSettlementHeader } from './x402.js';

const { Pool } = pg;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const VARIANT_ID = 'bts_h3_paid_route_swap_foundation';
const ROUTES = [
  { value: 'baseline', routeId: 'fee500' },
  { value: 'alternative', routeId: 'fee3000' },
] as const;

type PurchaseDatabaseRows = {
  operation: Record<string, unknown>;
  payment: Record<string, unknown>;
  delivery: Record<string, unknown>;
  transactionCost: Record<string, unknown>;
};
type FacilitatorGasCost = {
  transactionHash: string; payer: string; payerRole: 'facilitator'; gasUsed: string;
  effectiveGasPriceWei: string; gasCostWei: string; modeledGasFeeUsdcUnits: string;
  receiptBlockNumber: string; receiptBlockHash: string;
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_h3_${label}_missing`);
  return value;
}

function uint(value: unknown, label: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && (/^0x[0-9a-f]+$/i.test(value) || UINT.test(value))) return BigInt(value);
  throw new Error(`task_h3_${label}_invalid`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function h3CatalogReadHeaders(session: Pick<GenerationSession, 'runToken' | 'generationId'>, idempotencyKey = randomUUID()): Record<string, string> {
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(session.runToken) || !/^[0-9a-f-]{36}$/i.test(session.generationId)
    || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
    throw new Error('task_h3_catalog_auth_headers_invalid');
  }
  return {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey,
    'content-type': 'application/json',
  };
}

async function readUsdcBalance(ctx: ProbeContext, address: string, blockTag: string, operationId: string | null, label: string): Promise<bigint> {
  if (!ADDRESS.test(address)) throw new Error('task_h3_usdc_address_invalid');
  return ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest: ctx.runtime.manifest,
    address: address as `0x${string}`, blockTag, operationId, variantId: VARIANT_ID, label,
  });
}

async function readNativeBalance(ctx: ProbeContext, address: string, blockTag: string, operationId: string | null, label: string): Promise<bigint> {
  const response = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: ctx.env.envId,
    method: 'eth_getBalance', params: [address, blockTag], requestedBlock: blockTag,
    operationId, variantId: VARIANT_ID, label,
  });
  return uint(response.result, `${label}_result`);
}

async function latestBlock(ctx: ProbeContext, operationId: string | null, label: string): Promise<{ tag: string; number: string; hash: string }> {
  const response = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: ctx.env.envId,
    method: 'eth_blockNumber', params: [], operationId, variantId: VARIANT_ID, label: `${label}-height`,
  });
  if (typeof response.result !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(response.result)) {
    throw new Error('task_h3_block_height_invalid');
  }
  const tag = `0x${BigInt(response.result).toString(16)}`;
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: tag,
    operationId, variantId: VARIANT_ID, label: `${label}-identity`,
  });
  return { tag, number: BigInt(tag).toString(), hash: block.hash.toLowerCase() };
}

async function readPurchaseDatabaseRows(ctx: ProbeContext, session: GenerationSession, operationId: string, label: string): Promise<PurchaseDatabaseRows> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000, query_timeout: 8_000, application_name: 'web-agent-bench-bef-h3-purchase-readonly',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operation, payment, delivery, cost] = await Promise.all([
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query(`SELECT operation_id::text,env_id,generation_id::text,participant_id,operation_kind,status,receipt_status,
                           transaction_hash,selected_resource_id,selected_resource_sha256,selected_offer_id,selected_amount_units::text
                      FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
      client.query(`SELECT operation_id::text,payer_address,network,asset_address,amount_units::text,facilitator_address,
                           transaction_hash,receipt_status,token_delta_units::text,payer_balance_before::text,payer_balance_after::text,
                           facilitator_balance_before::text,facilitator_balance_after::text
                      FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
      client.query(`SELECT d.operation_id::text,d.resource_id,d.content_sha256,d.content_bytes::text
                      FROM bef_delivery d JOIN bef_operation o USING(operation_id)
                     WHERE o.env_id=$1 AND o.generation_id=$2::uuid AND d.operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
      client.query(`SELECT transaction_hash,payer_address,payer_role,receipt_status,transaction_from,receipt_from,
                           gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,modeled_gas_fee_usdc_units::text,
                           receipt_block_number::text,receipt_block_hash,base_l1_fee_status
                      FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
    ]);
    if (role.rows[0]?.role_name !== ctx.database.databaseRole || mode.rows[0]?.transaction_read_only !== 'on'
      || operation.rows.length !== 1 || payment.rows.length !== 1 || delivery.rows.length !== 1 || cost.rows.length !== 1) {
      throw new Error('task_h3_purchase_readonly_rows_invalid');
    }
    const rows = {
      operation: operation.rows[0] as Record<string, unknown>,
      payment: payment.rows[0] as Record<string, unknown>,
      delivery: delivery.rows[0] as Record<string, unknown>,
      transactionCost: cost.rows[0] as Record<string, unknown>,
    };
    await client.query('COMMIT');
    await ctx.evidence.writeObservation(`db/task-h3/${operationId}-purchase.json`, `task-h3-${operationId}-purchase-database`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId, variantId: VARIANT_ID,
      envId: session.envId, generationId: session.generationId, readOnly: true,
      databaseRole: ctx.database.databaseRole, transactionReadOnly: 'on', queryName: 'h3-purchase-payment-delivery-cost',
      rows: sanitizeValue(rows) as Record<string, unknown>,
    });
    return rows;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && error.message.startsWith('task_h3_')) throw error;
    throw new Error(`task_h3_${label}_database_observation_unavailable`);
  } finally {
    client.release();
    await pool.end();
  }
}

async function reconcileAmbiguousPurchase(ctx: ProbeContext, session: GenerationSession, operationId: string, label: string, responseStatus: number, returnedOperationId: string | null): Promise<void> {
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId, variantId: VARIANT_ID,
    label: `${label}-ambiguous-result-reconciliation`,
  });
  const operation = snapshot.operations.find((row) => String(row.operation_id) === operationId) ?? null;
  let receiptStatus: string = 'unknown';
  let receiptArtifactReference: string | null = null;
  const transactionHash = typeof operation?.transaction_hash === 'string' ? operation.transaction_hash : null;
  if (transactionHash && HASH.test(transactionHash)) {
    try {
      const receipt = await ctx.rpc.receipt({
        url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
        operationId, variantId: VARIANT_ID, label: `${label}-ambiguous-result-receipt-read`,
      });
      receiptStatus = receipt.status.toLowerCase() === '0x1' ? 'success' : receipt.status.toLowerCase();
      receiptArtifactReference = ctx.evidence.observations.at(-1)?.sourceArtifact ?? null;
    } catch {
      receiptStatus = 'unknown';
    }
  }
  await ctx.evidence.writeObservation(`task-purchase/${operationId}-ambiguous-result.json`, `task-purchase-${operationId}-ambiguous-result`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'read-only-ambiguous-settlement-reconciliation',
    operationId, variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId,
    outcome: 'unknown', responseStatus, returnedOperationId, persistedOperation: operation,
    persistedPaymentCount: snapshot.payments.filter((row) => String(row.operation_id) === operationId).length,
    persistedDeliveryCount: snapshot.deliveries.filter((row) => String(row.operation_id) === operationId).length,
    transactionHash, rpcReceiptStatus: receiptStatus, receiptArtifactReference,
    retryPerformed: false, signedPaymentResubmitted: false,
  });
}

function validateFacilitatorCost(row: Record<string, unknown>, transactionHash: string, facilitator: string, manifest: RuntimeManifest): FacilitatorGasCost {
  const gasUsed = requiredString(row.gas_used, 'facilitator_gas_used');
  const effectiveGasPriceWei = requiredString(row.effective_gas_price_wei, 'facilitator_gas_price');
  const gasCostWei = requiredString(row.gas_cost_wei, 'facilitator_gas_cost');
  const modeledFee = requiredString(row.modeled_gas_fee_usdc_units, 'facilitator_modeled_fee');
  const expectedModeled = (BigInt(gasCostWei) * BigInt(manifest.feePolicy.ethUsdcRateNumerator)
    / BigInt(manifest.feePolicy.ethUsdcRateDenominator)).toString();
  if (row.transaction_hash?.toString().toLowerCase() !== transactionHash.toLowerCase()
    || row.payer_role !== 'facilitator' || row.receipt_status !== 'success'
    || row.payer_address?.toString().toLowerCase() !== facilitator.toLowerCase()
    || row.transaction_from?.toString().toLowerCase() !== facilitator.toLowerCase()
    || row.receipt_from?.toString().toLowerCase() !== facilitator.toLowerCase()
    || uint(gasUsed, 'facilitator_gas_used') * uint(effectiveGasPriceWei, 'facilitator_gas_price') !== uint(gasCostWei, 'facilitator_gas_cost')
    || modeledFee !== expectedModeled || row.base_l1_fee_status !== 'unmodelled') {
    throw new Error('task_h3_facilitator_cost_mismatch');
  }
  return {
    transactionHash: transactionHash.toLowerCase(), payer: facilitator.toLowerCase(), payerRole: 'facilitator',
    gasUsed, effectiveGasPriceWei, gasCostWei, modeledGasFeeUsdcUnits: modeledFee,
    receiptBlockNumber: requiredString(row.receipt_block_number, 'facilitator_receipt_block'),
    receiptBlockHash: requiredString(row.receipt_block_hash, 'facilitator_receipt_block_hash').toLowerCase(),
  };
}

/**
 * Same-generation purchase helper for H3/U1. It only settles one explicitly
 * pinned catalog resource+offer and never resets or creates a generation.
 */
export async function purchasePinnedResourceInSession(ctx: ProbeContext, session: GenerationSession, input: {
  resourceId: string; offerId: string; variantId: string; label: string;
}): Promise<Record<string, unknown> & {
  operationId: string; transactionHash: string; amountUnits: string; deliveryProjection: ReturnType<typeof projectDeliveryEnvelope>;
  facilitatorGas: FacilitatorGasCost;
  receipt: { transactionHash: string; blockNumber: string; blockHash: string; gasUsed: string; effectiveGasPriceWei: string; gasCostWei: string };
  envelope: Record<string, unknown>;
}> {
  const manifest = ctx.runtime.manifest;
  const definition = manifest.x402.catalog?.find((entry) => entry.resourceId === input.resourceId);
  const offer = definition?.offers.find((entry) => entry.id === input.offerId);
  const resources = await loadPinnedResources(manifest);
  const pinned = resources.get(input.resourceId);
  if (!definition || !offer || !pinned || pinned.hash.toLowerCase() !== definition.resourceSha256.toLowerCase()
    || createHash('sha256').update(pinned.bytes).digest('hex') !== definition.resourceSha256.toLowerCase()) {
    throw new Error('task_h3_pinned_resource_or_offer_missing');
  }

  const catalogResponse = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${input.label}-public-catalog`, method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/catalog`),
    headers: h3CatalogReadHeaders(session),
    operationId: null, variantId: input.variantId,
  });
  const catalogBody = record(catalogResponse.body);
  if (catalogResponse.status !== 200 || !catalogBody) throw new Error(`task_h3_catalog_read_failed_${catalogResponse.status}`);
  const catalog = projectPinnedPublicCatalog({ response: catalogBody, manifest });
  const catalogOffer = catalog.offers.find((entry) => entry.resourceId === input.resourceId && entry.offerId === input.offerId);
  if (!catalogOffer || catalogOffer.advertisedTotalPriceUsdcUnits !== offer.amount) throw new Error('task_h3_public_catalog_offer_mismatch');

  const baseline = await latestBlock(ctx, null, `${input.label}-payment-baseline`);
  const payerUsdcBefore = await readUsdcBalance(ctx, session.payerAddress, baseline.tag, null, `${input.label}-payer-usdc-before`);
  const facilitatorUsdcBefore = await readUsdcBalance(ctx, catalog.facilitatorAddress, baseline.tag, null, `${input.label}-facilitator-usdc-before`);
  const payerNativeBefore = await readNativeBalance(ctx, session.payerAddress, baseline.tag, null, `${input.label}-payer-native-before`);
  const purchaseBody = { resourceId: input.resourceId, offerId: input.offerId };
  const idempotencyKey = randomUUID();
  const url = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/purchase`);
  const baseHeaders = {
    authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey, 'content-type': 'application/json',
  };
  let challengeOperationLookup: Awaited<ReturnType<typeof ctx.database.snapshot>> | null = null;
  const challenge = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${input.label}-payment-challenge`, method: 'POST', url,
    headers: baseHeaders, body: purchaseBody, operationId: null, variantId: input.variantId,
    resolveOperationId: async (_status, body) => {
      if (typeof record(body)?.operationId === 'string') return record(body)!.operationId as string;
      challengeOperationLookup = await ctx.database.snapshot({
        envId: session.envId, generationId: session.generationId, idempotencyKey,
        variantId: input.variantId, label: `${input.label}-challenge-operation-lookup`,
      });
      return challengeOperationLookup.operations.length === 1
        ? String(challengeOperationLookup.operations[0]?.operation_id) : null;
    },
  });
  const challengeBody = record(challenge.body);
  const operationId = challenge.operationId ?? (typeof challengeBody?.operationId === 'string' ? challengeBody.operationId : null);
  if (challenge.status !== 402 || !operationId || !UUID.test(operationId)) throw new Error(`task_h3_payment_challenge_failed_${challenge.status}`);
  challengeOperationLookup ??= await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, idempotencyKey,
    variantId: input.variantId, label: `${input.label}-challenge-operation-lookup`,
  });
  const keyedOperations = challengeOperationLookup.operations.filter((row) => String(row.operation_id) === operationId);
  const keyedOperation = keyedOperations.length === 1 ? keyedOperations[0]! : null;
  if (challengeOperationLookup.operations.length !== 1 || !keyedOperation
    || String(keyedOperation.env_id) !== session.envId
    || String(keyedOperation.generation_id) !== session.generationId
    || String(keyedOperation.participant_id) !== session.participantId) {
    throw new Error('task_h3_challenge_operation_idempotency_binding_mismatch');
  }
  const declaration = session.signer.httpClient.getPaymentRequiredResponse((name) => challenge.headers.get(name), challenge.body);
  const matchingRequirements = declaration.accepts.filter((candidate) => candidate.amount === offer.amount
    && candidate.scheme === manifest.x402.scheme && candidate.network === manifest.x402.network
    && candidate.asset.toLowerCase() === manifest.x402.asset.toLowerCase()
    && candidate.payTo.toLowerCase() === catalog.facilitatorAddress.toLowerCase());
  const requirements = matchingRequirements.length === 1 ? matchingRequirements[0]! : null;
  if (!requirements || declaration.x402Version !== 2 || !record(requirements.extra)
    || requirements.extra.assetTransferMethod !== manifest.x402.assetTransferMethod
    || requirements.extra.paymentFlow !== 'authorization'
    || requirements.extra.name !== manifest.x402.eip712Domain.name
    || requirements.extra.version !== manifest.x402.eip712Domain.version) {
    throw new Error('task_h3_payment_requirements_mismatch');
  }
  const pendingFacts = await readCaseDatabaseFacts(ctx, session, `${input.label}-database-after-challenge`, input.variantId);
  const pendingOperations = pendingFacts.operations.filter((row) => String(row.operation_id) === operationId);
  const pendingPayments = pendingFacts.payments.filter((row) => String(row.operation_id) === operationId);
  const pendingDeliveries = pendingFacts.deliveries.filter((row) => String(row.operation_id) === operationId);
  const pendingOperation = pendingOperations.length === 1 ? pendingOperations[0]! : null;
  if (!pendingOperation || pendingOperation.operation_kind !== 'purchase' || pendingOperation.status !== 'awaiting_payment'
    || pendingOperation.receipt_status !== 'unknown' || pendingOperation.transaction_hash !== null
    || pendingOperation.selected_offer_id !== offer.id || String(pendingOperation.selected_amount_units) !== offer.amount
    || pendingOperation.selected_resource_id !== definition.resourceId
    || String(pendingOperation.selected_resource_sha256).toLowerCase() !== definition.resourceSha256.toLowerCase()
    || pendingPayments.length !== 0 || pendingDeliveries.length !== 0) {
    throw new Error('task_h3_challenge_operation_not_pending_or_offer_mismatch');
  }
  const signed = await createSignedPayload(session.signer, declaration, requirements);
  const paid = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${input.label}-single-signed-purchase`, method: 'POST', url,
    headers: { ...baseHeaders, ...signed.headers }, body: purchaseBody, operationId, variantId: input.variantId,
    includeRawResponseBytes: true,
  });
  const paidBody = record(paid.body);
  if (paid.status !== 200 || paid.operationId !== operationId || !paidBody) {
    await reconcileAmbiguousPurchase(ctx, session, operationId, input.label, paid.status, paid.operationId);
    // Never replay a payment after an ambiguous response. This path records
    // read-only operation/receipt reconciliation and refuses to trade unless
    // authenticated delivered bytes were returned to this capture.
    throw new Error(`task_h3_purchase_result_unconfirmed_${paid.status}`);
  }
  const settlement = readSettlementHeader(session.signer.httpClient, paid.headers);
  const transactionHash = settlement?.transaction;
  if (!settlement?.success || typeof transactionHash !== 'string' || !HASH.test(transactionHash)) {
    await reconcileAmbiguousPurchase(ctx, session, operationId, input.label, paid.status, paid.operationId);
    throw new Error('task_h3_settlement_header_invalid');
  }
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId, variantId: input.variantId,
    label: `${input.label}-purchase-durable-snapshot`,
  });
  const operationRows = snapshot.operations.filter((row) => String(row.operation_id) === operationId);
  const paymentRows = snapshot.payments.filter((row) => String(row.operation_id) === operationId);
  const deliveryRows = snapshot.deliveries.filter((row) => String(row.operation_id) === operationId);
  if (operationRows.length !== 1 || paymentRows.length !== 1 || deliveryRows.length !== 1) {
    throw new Error('task_h3_purchase_durable_rows_missing');
  }
  const operation = operationRows[0]!;
  const payment = paymentRows[0]!;
  const delivery = deliveryRows[0]!;
  const deliveryProjection = projectDeliveryEnvelope({
    envelope: paidBody, expectedResourceId: definition.resourceId,
    expectedContentHash: definition.resourceSha256, provenanceId: definition.provenance.classification,
  });
  if (canonicalJson(deliveryProjection.parsedContent) !== canonicalJson(pinned.parsed)
    || delivery.resource_id !== definition.resourceId
    || String(delivery.content_sha256).toLowerCase() !== definition.resourceSha256.toLowerCase()
    || BigInt(String(delivery.content_bytes)) !== BigInt(pinned.bytes.byteLength)
    || operation.operation_kind !== 'purchase' || operation.status !== 'delivered' || operation.receipt_status !== 'success'
    || String(operation.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || payment.receipt_status !== 'success' || String(payment.amount_units) !== offer.amount
    || String(payment.token_delta_units) !== offer.amount
    || String(payment.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || String(payment.facilitator_address).toLowerCase() !== catalog.facilitatorAddress.toLowerCase()
    || String(payment.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('task_h3_purchase_database_or_delivery_binding_mismatch');
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
    operationId, variantId: input.variantId, label: `${input.label}-settlement-receipt`,
  });
  const tokenTransfers = transferEvents(receipt, manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === session.payerAddress.toLowerCase()
    && event.to.toLowerCase() === catalog.facilitatorAddress.toLowerCase() && event.amount === BigInt(offer.amount));
  if (receipt.status.toLowerCase() !== '0x1' || receipt.transactionHash.toLowerCase() !== transactionHash.toLowerCase()
    || receipt.from.toLowerCase() !== catalog.facilitatorAddress.toLowerCase() || tokenTransfers.length !== 1) {
    throw new Error('task_h3_payment_receipt_or_transfer_mismatch');
  }
  const payerUsdcAfter = await readUsdcBalance(ctx, session.payerAddress, receipt.blockNumber, operationId, `${input.label}-payer-usdc-after`);
  const facilitatorUsdcAfter = await readUsdcBalance(ctx, catalog.facilitatorAddress, receipt.blockNumber, operationId, `${input.label}-facilitator-usdc-after`);
  const payerNativeAfter = await readNativeBalance(ctx, session.payerAddress, receipt.blockNumber, operationId, `${input.label}-payer-native-after`);
  if (payerUsdcBefore - payerUsdcAfter !== BigInt(offer.amount)
    || facilitatorUsdcAfter - facilitatorUsdcBefore !== BigInt(offer.amount)
    || payerNativeAfter !== payerNativeBefore) throw new Error('task_h3_payment_balance_delta_mismatch');

  const dbRows = await readPurchaseDatabaseRows(ctx, session, operationId, input.label);
  const dbOperation = dbRows.operation;
  if (dbOperation.operation_kind !== 'purchase' || dbOperation.status !== 'delivered' || dbOperation.receipt_status !== 'success'
    || dbOperation.participant_id !== session.participantId || dbOperation.generation_id !== session.generationId
    || String(dbOperation.selected_resource_id) !== definition.resourceId
    || String(dbOperation.selected_resource_sha256).toLowerCase() !== definition.resourceSha256.toLowerCase()
    || String(dbOperation.selected_offer_id) !== offer.id || String(dbOperation.selected_amount_units) !== offer.amount
    || String(dbOperation.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('task_h3_purchase_operation_row_mismatch');
  }
  const facilitatorGas = validateFacilitatorCost(dbRows.transactionCost, transactionHash, catalog.facilitatorAddress, manifest);
  if (facilitatorGas.receiptBlockNumber !== BigInt(receipt.blockNumber).toString()
    || facilitatorGas.receiptBlockHash !== receipt.blockHash.toLowerCase()) throw new Error('task_h3_facilitator_receipt_binding_mismatch');

  const httpResponsePath = `task-purchase/${operationId}-paid-http-response.json`;
  await ctx.evidence.writeRawJson(httpResponsePath, paid.rawBody, 'actual-tool-http-paid-response-bytes');
  const contentPath = `task-purchase/${operationId}-delivered-content.json`;
  const contentBytes = Buffer.from(deliveryProjection.projection.contentBytes, 'base64');
  await ctx.evidence.writeRawJson(contentPath, contentBytes, 'actual-tool-http-delivered-content');
  const projectionPath = `task-purchase/${operationId}-delivery-projection.json`;
  await ctx.evidence.writeObservation(projectionPath, `task-purchase-${operationId}-delivery-projection`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http', operationId, variantId: input.variantId,
    projectionSchema: 'bef-delivery-envelope/v1', projection: deliveryProjection.projection,
    component: deliveryProjection.component, httpResponseArtifact: { path: httpResponsePath },
    rawContentArtifact: { path: contentPath, sha256: deliveryProjection.contentBytesSha256 },
  });
  return {
    operationId, transactionHash: transactionHash.toLowerCase(), paymentId: payment.payment_id,
    deliveryId: delivery.delivery_id, resourceId: definition.resourceId, resourceSha256: definition.resourceSha256,
    offerId: offer.id, amountUnits: offer.amount, contentBytes: pinned.bytes.byteLength,
    deliveryProjection, envelope: paidBody, facilitatorAddress: catalog.facilitatorAddress,
    facilitatorGas, receipt: {
      transactionHash: receipt.transactionHash, blockNumber: BigInt(receipt.blockNumber).toString(),
      blockHash: receipt.blockHash.toLowerCase(), gasUsed: uint(receipt.gasUsed, 'facilitator_gas_used').toString(),
      effectiveGasPriceWei: uint(receipt.effectiveGasPrice, 'facilitator_gas_price').toString(),
      gasCostWei: facilitatorGas.gasCostWei,
    },
    snapshots: {
      baselineBlock: baseline, payerUsdcBefore: payerUsdcBefore.toString(), payerUsdcAfter: payerUsdcAfter.toString(),
      facilitatorUsdcBefore: facilitatorUsdcBefore.toString(), facilitatorUsdcAfter: facilitatorUsdcAfter.toString(),
      payerNativeBeforeWei: payerNativeBefore.toString(), payerNativeAfterWei: payerNativeAfter.toString(),
    },
    artifacts: { httpResponsePath, contentPath, projectionPath },
  };
}

function deriveFee3000Minimum(ctx: ProbeContext, amount: bigint): { quote: bigint; minimum: bigint; slippageBps: number; pool: NonNullable<RuntimeManifest['contracts']['pool3000']> } {
  const manifest = ctx.runtime.manifest;
  const pool = manifest.contracts.pool3000;
  if (!pool || pool.fee !== 3000 || pool.quote.inputAssetId !== 'USDC' || pool.quote.outputAssetId !== 'WETH'
    || BigInt(pool.quote.amountInUnits) !== amount || !Number.isSafeInteger(manifest.swap.maxSlippageBps)
    || manifest.swap.maxSlippageBps < 0 || manifest.swap.maxSlippageBps >= 10_000
    || pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
    || pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()) {
    throw new Error('task_h3_selected_route_quote_unavailable');
  }
  const quote = BigInt(pool.quote.amountOutUnits);
  const minimum = quote * BigInt(10_000 - manifest.swap.maxSlippageBps) / 10_000n;
  if (quote <= 0n || minimum <= 0n || minimum > quote) throw new Error('task_h3_pinned_quote_invalid');
  return { quote, minimum, slippageBps: manifest.swap.maxSlippageBps, pool };
}

export async function captureH3PaidRouteSwapInSession(ctx: ProbeContext, session: GenerationSession): Promise<Record<string, unknown>> {
  const manifest = ctx.runtime.manifest;
  const marketDefinition = manifest.x402.catalog?.find((entry) => entry.resourceId === 'bef-market-state-brief-v1');
  if (!marketDefinition) throw new Error('task_h3_market_resource_pin_missing');
  const purchase = await purchasePinnedResourceInSession(ctx, session, {
    resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', variantId: VARIANT_ID, label: 'task-h3-market-brief',
  });
  const route = projectRouteDelivery({
    envelope: purchase.envelope, expectedResourceId: String(purchase.resourceId),
    expectedContentHash: String(purchase.resourceSha256),
    provenanceId: marketDefinition.provenance.classification, routes: ROUTES,
  });
  const selectedFeeTier = route.selectedRouteId === 'fee500' ? 500 : route.selectedRouteId === 'fee3000' ? 3000 : null;
  if (!selectedFeeTier) throw new Error('task_h3_route_mapping_invalid');
  // The baseline 500 pool currently has no pinned USDC -> WETH quote. Keep it
  // allowed in the route predicate, but fail closed if delivered data selects it.
  if (selectedFeeTier !== 3000) throw new Error('task_h3_selected_fee500_quote_unavailable');
  const amount = BigInt('100000');
  const quote = deriveFee3000Minimum(ctx, amount);
  const recipient = session.payerAddress;
  const before = await readNativeStateInSession(ctx, session, 'task-h3-before-approval', VARIANT_ID);
  if (BigInt(before.blockNumber) < BigInt(String(purchase.receipt.blockNumber))) {
    throw new Error('task_h3_purchase_to_trade_chronology_invalid');
  }
  if (BigInt(before.payerUsdcUnits) < amount || before.usdcAllowanceUnits !== '0' || before.wethAllowanceUnits !== '0') {
    throw new Error('task_h3_generation_trade_prestate_invalid');
  }
  const approval = await approveUsdcInSession(ctx, session, amount, VARIANT_ID, 'h3-approve-usdc');
  if (approval.state.usdcAllowanceUnits !== amount.toString() || approval.state.payerUsdcUnits !== before.payerUsdcUnits
    || approval.state.payerWethUnits !== before.payerWethUnits || approval.state.wethAllowanceUnits !== before.wethAllowanceUnits
    || approval.state.poolUsdcUnits !== before.poolUsdcUnits || approval.state.poolWethUnits !== before.poolWethUnits
    || BigInt(before.payerNativeWei) - BigInt(approval.state.payerNativeWei) !== approval.gasCostWei) {
    throw new Error('task_h3_approval_effect_delta_mismatch');
  }
  const swap = await swapUsdcToWethInSession(ctx, session, {
    amount, minimumOutput: quote.minimum, recipient, variantId: VARIANT_ID, label: 'h3-usdc-to-weth',
  });
  const swapGasLimit = 400_000n;
  const approvalGasLimit = 100_000n;
  if (BigInt(approval.state.payerUsdcUnits) - BigInt(swap.state.payerUsdcUnits) !== amount
    || BigInt(swap.state.payerWethUnits) - BigInt(approval.state.payerWethUnits) !== swap.output
    || BigInt(swap.state.poolUsdcUnits) - BigInt(approval.state.poolUsdcUnits) !== amount
    || BigInt(approval.state.poolWethUnits) - BigInt(swap.state.poolWethUnits) !== swap.output
    || BigInt(approval.state.usdcAllowanceUnits) - BigInt(swap.state.usdcAllowanceUnits) !== amount
    || swap.state.wethAllowanceUnits !== approval.state.wethAllowanceUnits
    || BigInt(approval.state.payerNativeWei) - BigInt(swap.state.payerNativeWei) !== swap.gasCostWei) {
    throw new Error('task_h3_swap_effect_delta_mismatch');
  }
  if (swap.input !== amount) throw new Error('task_h3_pool_input_not_selected_amount');
  if (!(BigInt(String(purchase.receipt.blockNumber)) < BigInt(approval.receipt.blockNumber)
    && BigInt(approval.receipt.blockNumber) < BigInt(swap.receipt.blockNumber))) {
    throw new Error('task_h3_action_receipt_order_invalid');
  }
  const participantGasWei = approval.gasCostWei + swap.gasCostWei;
  const participantGasUnits = participantGasWei * BigInt(manifest.feePolicy.ethUsdcRateNumerator)
    / BigInt(manifest.feePolicy.ethUsdcRateDenominator);
  const dexFeeUnits = (swap.input * BigInt(selectedFeeTier) + 999_999n) / 1_000_000n;
  const serviceChargeUnits = BigInt(String(purchase.amountUnits));
  const facilitatorGasUnits = BigInt(String(purchase.facilitatorGas.modeledGasFeeUsdcUnits));
  const participantObservedExpenseUnits = serviceChargeUnits + participantGasUnits + dexFeeUnits;
  const localOperatingExpenseUnits = participantObservedExpenseUnits + facilitatorGasUnits;
  const localCandidateBUnits = participantObservedExpenseUnits * 2n;
  const feeCapWei = BigInt(manifest.feePolicy.baseFeeWei) + BigInt(manifest.feePolicy.priorityFeeWei);
  const maxParticipantGasUnits = approvalGasLimit + swapGasLimit;
  const conservativeReserveRequirementWei = maxParticipantGasUnits * feeCapWei * 2n;
  const initialNativeWei = BigInt(before.payerNativeWei);
  if (initialNativeWei <= conservativeReserveRequirementWei) throw new Error('task_h3_native_reserve_headroom_insufficient');

  const capture = {
    schemaVersion: 'bts-h3-paid-route-swap-foundation/v1',
    classification: 'local_fork_public_tool_reference_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    paidReference: {
      operationId: purchase.operationId, paymentId: purchase.paymentId, deliveryId: purchase.deliveryId,
      transactionHash: purchase.transactionHash, resourceId: purchase.resourceId, resourceSha256: purchase.resourceSha256,
      offerId: purchase.offerId, amountUnits: purchase.amountUnits, contentBytes: purchase.contentBytes,
      facilitatorAddress: purchase.facilitatorAddress, receipt: purchase.receipt, facilitatorGas: purchase.facilitatorGas,
      deliveryProjection: route.projection, component: route.component, routeObjective: route.routeObjective,
      selectedRouteId: route.selectedRouteId, routeCode: route.projection.routeCode,
      deliveryContentBytesSha256: route.contentBytesSha256, artifacts: purchase.artifacts,
    },
    trade: {
      feeTier: selectedFeeTier, poolAddress: quote.pool.address, poolCodeHash: quote.pool.codeHash,
      inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: amount.toString(), recipient,
      pinnedQuoteOutUnits: quote.quote.toString(), slippageBps: quote.slippageBps,
      minimumOutputUnits: quote.minimum.toString(), observedOutputUnits: swap.output.toString(),
      approval: {
        operationId: approval.action.operationId, transactionHash: approval.action.transactionHash,
        gasUsed: uint(approval.receipt.gasUsed, 'approval_gas_used').toString(),
        effectiveGasPriceWei: uint(approval.receipt.effectiveGasPrice, 'approval_effective_gas_price').toString(),
        gasCostWei: approval.gasCostWei.toString(), persistedCost: approval.persistedCost,
      },
      swap: {
        operationId: swap.action.operationId, transactionHash: swap.action.transactionHash,
        gasUsed: uint(swap.receipt.gasUsed, 'swap_gas_used').toString(),
        effectiveGasPriceWei: uint(swap.receipt.effectiveGasPrice, 'swap_effective_gas_price').toString(),
        gasCostWei: swap.gasCostWei.toString(), persistedCost: swap.persistedCost,
      },
      snapshots: { before, afterApproval: approval.state, afterSwap: swap.state },
    },
    localExpenseProfile: {
      classification: 'post_capture_local_profile_only_not_release_pin_or_production_budget',
      serviceChargeUsdcUnits: serviceChargeUnits.toString(),
      facilitatorGasUsdcUnits: facilitatorGasUnits.toString(),
      participantApprovalAndSwapGasUsdcUnits: participantGasUnits.toString(),
      participantGasWei: participantGasWei.toString(), gasCostConversion: 'aggregate participant gas wei converted once; floor by pinned rational rate',
      dexFeeUsdcUnits: dexFeeUnits.toString(), dexFeeDerivation: 'ceil(observed pool Swap input units * selected fee tier / 1,000,000)',
      facilitatorGasExcludedFromParticipantExpense: true,
      actualPrincipalUsdcUnits: amount.toString(), principalExcludedFromExpense: true,
      actualParticipantExpenseUsdcUnits: participantObservedExpenseUnits.toString(),
      localOperatingExpenseIncludingFacilitatorGasUsdcUnits: localOperatingExpenseUnits.toString(),
      candidateBUsdcUnits: localCandidateBUnits.toString(), candidateBFormula: '2 * actualParticipantExpenseUsdcUnits',
      nativeReserve: {
        observedInitialPayerNativeWei: initialNativeWei.toString(),
        participantGasLimits: { approval: approvalGasLimit.toString(), swap: swapGasLimit.toString(), total: maxParticipantGasUnits.toString() },
        pinnedFeeCapWei: feeCapWei.toString(), conservativeReserveRequirementWei: conservativeReserveRequirementWei.toString(),
        localHeadroomWei: (initialNativeWei - conservativeReserveRequirementWei).toString(),
      },
    },
    noAcceptanceClaim: 'No task release was activated, no score was posted, and this local capture is not mainnet or production evidence.',
  };
  const artifactPath = 'task-h3/h3-paid-route-swap-foundation.json';
  await ctx.evidence.writeObservation(artifactPath, 'task-h3-paid-route-swap-foundation', {
    ...capture, boundary: 'actual-tool-http-and-readonly-observer', operationId: String(purchase.operationId), variantId: VARIANT_ID,
    envId: session.envId, generationId: session.generationId,
  });
  const artifact = ctx.evidence.artifacts.find((entry) => entry.path === artifactPath);
  if (!artifact) throw new Error('task_h3_capture_artifact_missing');
  return { ...capture, artifact: { path: artifact.path, sha256: artifact.sha256 }, rawArtifacts: ctx.evidence.artifacts.map(({ path, sha256, boundary }) => ({ path, sha256, boundary })) };
}

export async function fenceH3Generation(ctx: ProbeContext, session: GenerationSession): Promise<Record<string, unknown>> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-h3-generation-fence', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/generations/${session.generationId}/fence`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' }, body: {},
    operationId: null, variantId: VARIANT_ID,
  });
  const body = record(response.body);
  if (response.status !== 200 || body?.status !== 'fenced' || body?.signerErased !== true) throw new Error(`task_h3_generation_fence_failed_${response.status}`);
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId: VARIANT_ID, label: 'task-h3-generation-after-fence',
  });
  if (snapshot.generation.length !== 1 || snapshot.generation[0]?.status !== 'fenced') throw new Error('task_h3_generation_fence_not_persisted');
  return { status: 'fenced', signerErased: true, databaseGeneration: snapshot.generation[0] };
}
