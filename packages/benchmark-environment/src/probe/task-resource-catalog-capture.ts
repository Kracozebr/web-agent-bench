/** Real local-fork x402 captures for two pinned resources and a cross-resource replay denial. */
import { randomUUID, createHash } from 'node:crypto';
import pg from 'pg';
import type { Address } from 'viem';
import { apiPath, newParticipantId } from './environment.js';
import type { ProbeContext } from './runner.js';
import { createEphemeralSigner, createSignedPayload, readSettlementHeader } from './x402.js';
import { transferEvents } from './rpc.js';
import { loadPinnedResources } from '../resource.js';

const { Pool } = pg;
const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || !value) throw new Error(`task_resource_catalog_${name}_missing`);
  return value;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readDurableRows(ctx: ProbeContext, session: { envId: string; generationId: string }, operationId: string, observationSuffix = operationId): Promise<{
  operation: Record<string, unknown> | null;
  payment: Record<string, unknown> | null;
  delivery: Record<string, unknown> | null;
  generationCount: string;
  purchaseCount: string;
  paymentCount: string;
  deliveryCount: string;
}> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: 'web-agent-bench-bef-resource-catalog-readonly',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operation, payment, delivery, counts] = await Promise.all([
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query(`SELECT operation_id::text,status,receipt_status,transaction_hash,request_sha256,
                           selected_offer_id,selected_amount_units::text,selected_resource_id,selected_resource_sha256
                      FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
      client.query(`SELECT payer_address,network,asset_address,amount_units::text,facilitator_address,
                           transaction_hash,receipt_status,token_delta_units::text,payer_balance_before::text,
                           payer_balance_after::text,facilitator_balance_before::text,facilitator_balance_after::text
                      FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid`,
        [session.envId, session.generationId, operationId]),
      client.query(`SELECT resource_id,content_sha256,content_bytes::text
                      FROM bef_delivery WHERE operation_id=$1`, [operationId]),
      client.query(`SELECT
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid)::text AS generation_count,
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_kind='purchase')::text AS purchase_count,
        (SELECT count(*) FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid)::text AS payment_count,
        (SELECT count(*) FROM bef_delivery d JOIN bef_operation o USING(operation_id) WHERE o.env_id=$1 AND o.generation_id=$2::uuid)::text AS delivery_count`,
        [session.envId, session.generationId]),
    ]);
    const databaseRole = role.rows[0]?.role_name ?? '';
    const transactionReadOnly = mode.rows[0]?.transaction_read_only ?? '';
    if (databaseRole !== ctx.database.databaseRole || transactionReadOnly !== 'on') throw new Error('task_resource_catalog_database_not_readonly');
    const result = {
      operation: operation.rows[0] as Record<string, unknown> | undefined ?? null,
      payment: payment.rows[0] as Record<string, unknown> | undefined ?? null,
      delivery: delivery.rows[0] as Record<string, unknown> | undefined ?? null,
      generationCount: counts.rows[0]?.generation_count ?? '0',
      purchaseCount: counts.rows[0]?.purchase_count ?? '0',
      paymentCount: counts.rows[0]?.payment_count ?? '0',
      deliveryCount: counts.rows[0]?.delivery_count ?? '0',
    };
    await ctx.evidence.writeObservation(`db/task-resource-catalog-${observationSuffix}.json`, `task-resource-catalog-${observationSuffix}`, {
      schemaVersion: 'bef-db-observation/v1',
      boundary: 'readonly-database',
      operationId,
      variantId: 'task_m3_resource_catalog_capture',
      envId: session.envId,
      generationId: session.generationId,
      readOnly: true,
      databaseRole,
      transactionReadOnly,
      queryName: 'resource-catalog-operation-payment-delivery-binding',
      rows: result,
    });
    await client.query('ROLLBACK');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && /^task_resource_catalog_[a-z0-9_]+$/.test(error.message)) throw error;
    const code = isRecord(error) && typeof error.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code)
      ? `_${error.code.toLowerCase()}` : '';
    throw new Error(`task_resource_catalog_database_observation_unavailable${code}`);
  } finally {
    client.release();
    await pool.end();
  }
}

export async function capturePinnedResourceCatalogPurchases(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const manifest = ctx.runtime.manifest;
  const catalog = manifest.x402.catalog;
  if (!catalog || catalog.length < 2) throw new Error('task_resource_catalog_two_pinned_resources_required');
  const pinnedResources = await loadPinnedResources(manifest);
  const variantId = 'task_m3_resource_catalog_capture';
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) throw new Error('task_resource_catalog_reset_route_unavailable');
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-resource-catalog-reset', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_resource_catalog_reset_failed_${reset.status}`);

  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(ctx.scenarioId);
  const generation = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-resource-catalog-generation', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId,
  });
  if (generation.status < 200 || generation.status >= 300) throw new Error(`task_resource_catalog_generation_failed_${generation.status}`);
  const generationBody = isRecord(generation.body) ? generation.body : null;
  const session = {
    envId: requiredString(generationBody?.envId, 'env_id'),
    generationId: requiredString(generationBody?.generationId, 'generation_id'),
    participantId,
    payerAddress: signer.payerAddress,
    runToken: requiredString(generationBody?.runToken ?? (isRecord(generationBody?.participant) ? generationBody.participant.runToken : undefined), 'run_token'),
  };
  if (session.envId !== ctx.env.envId || generationBody?.payerAddress?.toString().toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('task_resource_catalog_generation_identity_mismatch');
  }
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  const headers = (key: string) => ({
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': key,
    'content-type': 'application/json',
  });
  const catalogResponse = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-resource-catalog-public-list', method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/catalog`),
    headers: headers(randomUUID()), body: undefined, operationId: null, variantId,
  });
  if (catalogResponse.status !== 200 || !isRecord(catalogResponse.body) || !Array.isArray(catalogResponse.body.catalog)) {
    throw new Error(`task_resource_catalog_http_failed_${catalogResponse.status}`);
  }
  const advertised = catalogResponse.body.catalog;
  if (advertised.length !== catalog.length) throw new Error('task_resource_catalog_count_mismatch');
  let facilitatorAddress: Address | null = null;
  for (const [index, entry] of catalog.entries()) {
    const listed = advertised[index];
    if (!isRecord(listed) || listed.resourceId !== entry.resourceId || listed.resourceSha256 !== entry.resourceSha256
      || listed.schema !== entry.schema || !Array.isArray(listed.offers)
      || listed.offers.length !== entry.offers.length) throw new Error('task_resource_catalog_public_binding_mismatch');
    for (const [offerIndex, offer] of entry.offers.entries()) {
      const listedOffer = listed.offers[offerIndex];
      if (!isRecord(listedOffer) || listedOffer.id !== offer.id || !isRecord(listedOffer.payment)
        || listedOffer.payment.amount !== offer.amount || listedOffer.payment.asset?.toString().toLowerCase() !== manifest.x402.asset.toLowerCase()) {
        throw new Error('task_resource_catalog_public_offer_binding_mismatch');
      }
      const payTo = listedOffer.payment.payTo;
      if (typeof payTo !== 'string' || !/^0x[0-9a-f]{40}$/i.test(payTo)) throw new Error('task_resource_catalog_facilitator_address_invalid');
      if (facilitatorAddress && facilitatorAddress.toLowerCase() !== payTo.toLowerCase()) throw new Error('task_resource_catalog_facilitator_address_mismatch');
      facilitatorAddress = payTo as Address;
    }
  }
  if (!facilitatorAddress) throw new Error('task_resource_catalog_facilitator_address_missing');
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: 'task-resource-catalog-generation' });
  const results: Array<Record<string, unknown>> = [];
  let wrongResourceReplay: Record<string, unknown> | null = null;

  for (const [index, definition] of catalog.slice(0, 2).entries()) {
    const resource = pinnedResources.get(definition.resourceId);
    if (!resource || resource.hash !== definition.resourceSha256 || sha256(resource.bytes) !== definition.resourceSha256) {
      throw new Error('task_resource_catalog_local_content_binding_mismatch');
    }
    const offer = definition.offers[0]!;
    const purchaseBody = { resourceId: definition.resourceId, offerId: offer.id };
    const idempotencyKey = randomUUID();
    const purchaseUrl = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/purchase`);
    const challenge = await ctx.transport.request({
      boundary: 'actual-tool-http', observationId: `task-resource-catalog-${index}-payment-challenge`, method: 'POST',
      url: purchaseUrl, headers: headers(idempotencyKey), body: purchaseBody, operationId: null, variantId,
      resolveOperationId: async (_status, body) => {
        if (isRecord(body) && typeof body.operationId === 'string') return body.operationId;
        const rows = await ctx.database.snapshot({
          envId: session.envId, generationId: session.generationId, idempotencyKey,
          variantId, label: `task-resource-catalog-${index}-challenge-operation-lookup`,
        });
        return rows.operations.length ? String(rows.operations[0]?.operation_id) : null;
      },
    });
    if (challenge.status !== 402 || !challenge.operationId || !isRecord(challenge.body)) {
      throw new Error(`task_resource_catalog_challenge_failed_${index}_${challenge.status}`);
    }
    const declaration = signer.httpClient.getPaymentRequiredResponse((name) => challenge.headers.get(name), challenge.body);
    const requirements = declaration.accepts.find((candidate) => candidate.amount === offer.amount
      && candidate.scheme === manifest.x402.scheme && candidate.network === manifest.x402.network
      && candidate.asset.toLowerCase() === manifest.x402.asset.toLowerCase());
    if (!requirements || requirements.payTo.toLowerCase() !== facilitatorAddress.toLowerCase()) {
      throw new Error(`task_resource_catalog_payment_requirements_mismatch_${index}`);
    }
    const signed = await createSignedPayload(signer, declaration, requirements);
    const payerBefore = await ctx.rpc.tokenBalance({
      url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
      address: signer.payerAddress, operationId: challenge.operationId, variantId,
      label: `task-resource-catalog-${index}-payer-before`,
    });
    const facilitatorBefore = await ctx.rpc.tokenBalance({
      url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
      address: facilitatorAddress, operationId: challenge.operationId, variantId,
      label: `task-resource-catalog-${index}-facilitator-before`,
    });
    const paid = await ctx.transport.request({
      boundary: 'actual-tool-http', observationId: `task-resource-catalog-${index}-signed-purchase`, method: 'POST',
      url: purchaseUrl, headers: { ...headers(idempotencyKey), ...signed.headers }, body: purchaseBody,
      operationId: challenge.operationId, variantId, includeRawResponseBytes: true,
    });
    if (paid.status !== 200 || paid.operationId !== challenge.operationId || !isRecord(paid.body)) {
      throw new Error(`task_resource_catalog_delivery_failed_${index}_${paid.status}`);
    }
    const settlement = readSettlementHeader(signer.httpClient, paid.headers);
    if (!settlement?.success || typeof settlement.transaction !== 'string' || !/^0x[0-9a-f]{64}$/i.test(settlement.transaction)) {
      throw new Error(`task_resource_catalog_settlement_header_invalid_${index}`);
    }
    const responseResourceBytes = Buffer.from(requiredString(paid.body.contentBytes, 'content_bytes'), 'base64');
    if (paid.body.resourceId !== definition.resourceId || paid.body.contentHash !== definition.resourceSha256
      || sha256(responseResourceBytes) !== definition.resourceSha256 || !responseResourceBytes.equals(resource.bytes)
      || JSON.stringify(paid.body.content) !== JSON.stringify(resource.parsed)) {
      throw new Error(`task_resource_catalog_delivered_content_mismatch_${index}`);
    }
    const receipt = await ctx.rpc.receipt({
      url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: settlement.transaction,
      operationId: challenge.operationId, variantId, label: `task-resource-catalog-${index}-settlement-receipt`,
    });
    if (receipt.status.toLowerCase() !== '0x1') throw new Error(`task_resource_catalog_receipt_not_success_${index}`);
    const transfer = transferEvents(receipt, manifest.contracts.usdc.address).filter((event) =>
      event.from.toLowerCase() === signer.payerAddress.toLowerCase()
      && event.to.toLowerCase() === facilitatorAddress.toLowerCase()
      && event.amount === BigInt(offer.amount));
    const payerAfter = await ctx.rpc.tokenBalance({
      url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
      address: signer.payerAddress, operationId: challenge.operationId, variantId,
      label: `task-resource-catalog-${index}-payer-after`,
    });
    const facilitatorAfter = await ctx.rpc.tokenBalance({
      url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
      address: facilitatorAddress, operationId: challenge.operationId, variantId,
      label: `task-resource-catalog-${index}-facilitator-after`,
    });
    if (transfer.length !== 1 || payerBefore - payerAfter !== BigInt(offer.amount)
      || facilitatorAfter - facilitatorBefore !== BigInt(offer.amount)) {
      throw new Error(`task_resource_catalog_receipt_effect_mismatch_${index}`);
    }
    await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, operationId: challenge.operationId, variantId, label: `task-resource-catalog-${index}-operation` });
    const rows = await readDurableRows(ctx, session, challenge.operationId);
    const operation = rows.operation;
    const payment = rows.payment;
    const delivery = rows.delivery;
    if (!operation || !payment || !delivery || operation.status !== 'delivered' || operation.receipt_status !== 'success'
      || operation.transaction_hash !== settlement.transaction
      || operation.selected_offer_id !== offer.id || operation.selected_amount_units !== offer.amount
      || operation.selected_resource_id !== definition.resourceId || operation.selected_resource_sha256 !== definition.resourceSha256
      || payment.receipt_status !== 'success' || payment.amount_units !== offer.amount || payment.token_delta_units !== offer.amount
      || payment.payer_address?.toString().toLowerCase() !== signer.payerAddress.toLowerCase()
      || payment.transaction_hash !== settlement.transaction
      || delivery.resource_id !== definition.resourceId || delivery.content_sha256 !== definition.resourceSha256
      || Number(delivery.content_bytes) !== resource.bytes.byteLength) {
      throw new Error(`task_resource_catalog_database_binding_mismatch_${index}`);
    }
    results.push({
      resourceId: definition.resourceId,
      resourceSha256: definition.resourceSha256,
      offerId: offer.id,
      amountUnits: offer.amount,
      operationId: challenge.operationId,
      paymentTransactionHash: settlement.transaction,
      receiptStatus: receipt.status,
      deliveredContentBytes: responseResourceBytes.byteLength,
      selectedResourcePersisted: true,
      selectedOfferPersisted: true,
      paymentAndDeliveryPersisted: true,
      observedPayerDeltaUnits: (payerAfter - payerBefore).toString(),
      observedFacilitatorDeltaUnits: (facilitatorAfter - facilitatorBefore).toString(),
    });

    if (index === 0) {
      const beforeReplay = { generationCount: rows.generationCount, purchaseCount: rows.purchaseCount, paymentCount: rows.paymentCount, deliveryCount: rows.deliveryCount };
      const other = catalog[1]!;
      const wrong = await ctx.transport.request({
        boundary: 'actual-tool-http', observationId: 'task-resource-catalog-cross-resource-idempotency-replay', method: 'POST',
        url: purchaseUrl, headers: headers(idempotencyKey),
        body: { resourceId: other.resourceId, offerId: other.offers[0]!.id },
        operationId: challenge.operationId, variantId,
      });
      if (wrong.status !== 409 || !isRecord(wrong.body) || wrong.body.error !== 'idempotency_key_conflict') {
        throw new Error(`task_resource_catalog_cross_resource_replay_not_denied_${wrong.status}`);
      }
      const afterReplay = await readDurableRows(ctx, session, challenge.operationId, `${challenge.operationId}-after-cross-resource-replay`);
      if (JSON.stringify(beforeReplay) !== JSON.stringify({
        generationCount: afterReplay.generationCount, purchaseCount: afterReplay.purchaseCount,
        paymentCount: afterReplay.paymentCount, deliveryCount: afterReplay.deliveryCount,
      }) || afterReplay.operation?.selected_resource_id !== definition.resourceId
        || afterReplay.operation?.selected_offer_id !== offer.id
        || afterReplay.payment?.transaction_hash !== settlement.transaction
        || afterReplay.delivery?.resource_id !== definition.resourceId) {
        throw new Error('task_resource_catalog_cross_resource_replay_changed_durable_state');
      }
      wrongResourceReplay = {
        status: wrong.status,
        error: wrong.body.error,
        selectedOperationId: challenge.operationId,
        originalResourceId: definition.resourceId,
        attemptedResourceId: other.resourceId,
        durableStateUnchanged: true,
        paymentCount: afterReplay.paymentCount,
        deliveryCount: afterReplay.deliveryCount,
      };
    }
  }

  if (!wrongResourceReplay) throw new Error('task_resource_catalog_wrong_resource_replay_not_run');
  return {
    schemaVersion: 'bts-resource-catalog-probe/v1',
    classification: 'selected_executor_resource_catalog_capture_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress },
    catalog: advertised,
    purchases: results,
    wrongResourceReplay,
  };
}
