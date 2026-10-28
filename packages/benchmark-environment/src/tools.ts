import { randomUUID, timingSafeEqual } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { FastifyAdapter } from '@x402/fastify';
import { createPublicClient, decodeEventLog, http, parseAbi, type Address, type Hex } from 'viem';
import { base } from 'viem/chains';
import { withEnvironmentAdvisoryLock, withTransaction, insertOperation, runTokenHash, sha256 } from './db.js';
import type { ApplicationRuntime, RuntimeEnvironment } from './runtime.js';
import type { PaymentProtocol } from './protocol.js';
import { facilitatorRequestScope } from './protocol.js';
import { mismatchedResource } from './resource.js';
import { pinnedOfferRequirementsMatch, pinnedResource, resolveOfferResourceId, selectedPinnedResourceOffer } from './offers.js';
import {
  PayRequestSchema,
  RetrieveQuerySchema,
  paidReceipt,
  responseSha256,
  sameAcceptedPaymentTerms,
  verifyInspectionRead,
  type AcceptedPaymentTerms,
} from './pay-retrieve.js';

const resourceTransferAbi = parseAbi([
  'event Transfer(address indexed from,address indexed to,uint256 value)',
] as const);
const balanceAbi = parseAbi(['function balanceOf(address) view returns (uint256)'] as const);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));

type AuthorizedRequest = {
  env: RuntimeEnvironment;
  envId: string;
  generationId: string;
  participantId: string;
  payerAddress: Address;
  resourceVariant: string;
  idempotencyKey: string;
  tokenHash: string;
};

type PaymentResponseMode = 'combined' | 'deferred_delivery';
type Operation = { operationId: string; status: string; requestHash: string; paymentResponseMode: PaymentResponseMode; isNew: boolean };

function constantTimeEqual(leftValue: string, rightValue: string): boolean {
  const left = Buffer.from(leftValue);
  const right = Buffer.from(rightValue);
  return left.length === right.length && timingSafeEqual(left, right);
}

function safeString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function routeEnvironment(runtime: ApplicationRuntime, request: FastifyRequest): RuntimeEnvironment | null {
  const envId = (request.params as { envId?: unknown }).envId;
  return typeof envId === 'string' ? runtime.envs.get(envId) ?? null : null;
}

async function authorizeParticipant(
  runtime: ApplicationRuntime,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<AuthorizedRequest | null> {
  const env = routeEnvironment(runtime, request);
  if (!env) {
    await reply.code(404).send({ error: 'environment_not_found' });
    return null;
  }
  const authorization = request.headers.authorization;
  const generationId = request.headers['x-bef-generation'];
  const idempotencyKey = request.headers['idempotency-key'];
  const match = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(authorization) : null;
  if (!match || typeof generationId !== 'string' || !uuidPattern.test(generationId) ||
      typeof idempotencyKey !== 'string' || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
    await reply.code(401).send({ error: 'scoped_authentication_required' });
    return null;
  }
  const tokenHash = runTokenHash(match[1]!);
  const result = await runtime.pool.query<{
    participant_id: string;
    payer_address: string;
    resource_variant: string;
    run_token_sha256: string;
  }>(
    `SELECT participant_id,payer_address,resource_variant,run_token_sha256
       FROM bef_generation
      WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp()`,
    [env.id, generationId],
  );
  const generation = result.rows[0];
  if (!generation || !constantTimeEqual(tokenHash, generation.run_token_sha256)) {
    await reply.code(403).send({ error: 'generation_scope_denied' });
    return null;
  }
  return {
    env,
    envId: env.id,
    generationId,
    participantId: generation.participant_id,
    payerAddress: generation.payer_address as Address,
    resourceVariant: generation.resource_variant,
    idempotencyKey,
    tokenHash,
  };
}

async function operationForRequest(runtime: ApplicationRuntime, auth: AuthorizedRequest, input: {
  requestHash: string;
  kind: string;
  paymentResponseMode?: PaymentResponseMode;
}): Promise<Operation> {
  return withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => {
    const generation = await runtime.pool.query(
      `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp()`,
      [auth.envId, auth.generationId],
    );
    if (!generation.rowCount) throw new Error('generation_fenced');
    const operation = await insertOperation(runtime.pool, {
      envId: auth.envId,
      generationId: auth.generationId,
      participantId: auth.participantId,
      idempotencyKey: auth.idempotencyKey,
      requestHash: input.requestHash,
      kind: input.kind,
      ...(input.paymentResponseMode === undefined ? {} : { paymentResponseMode: input.paymentResponseMode }),
    });
    if (!constantTimeEqual(operation.requestHash, input.requestHash)) throw new Error('idempotency_key_reused_for_different_request');
    if (operation.paymentResponseMode !== (input.paymentResponseMode ?? 'combined')) throw new Error('payment_response_mode_conflict');
    if (!operation.isNew && operation.status === 'awaiting_payment' && input.kind === 'offer') {
      await runtime.pool.query(
        `UPDATE bef_operation SET operation_kind='offer',status='accepted',receipt_status='not_submitted'
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='awaiting_payment'`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      operation.status = 'accepted';
    }
    return operation;
  });
}

function expectedPaymentTerms(runtime: ApplicationRuntime, auth: AuthorizedRequest, selected: NonNullable<ReturnType<typeof selectedPinnedResourceOffer>>): AcceptedPaymentTerms {
  return {
    scheme: runtime.manifest.x402.scheme,
    network: runtime.manifest.x402.network,
    asset: runtime.manifest.x402.asset,
    amount: selected.offer.amount,
    payTo: auth.env.facilitatorAddress,
    transferMethod: runtime.manifest.x402.assetTransferMethod,
  };
}

function catalogResponse(runtime: ApplicationRuntime, auth: AuthorizedRequest, operationId: string): Record<string, unknown> {
  const catalog = [...runtime.resources.values()].map((resource) => {
    const definition = pinnedResource(runtime.manifest, resource.resourceId);
    if (!definition || resource.hash !== definition.resourceSha256) throw new Error('Pinned resource catalog is inconsistent');
    return {
      resourceId: resource.resourceId,
      resourceSha256: resource.hash,
      contentType: resource.contentType,
      ...(definition.dataType === undefined ? {} : { dataType: definition.dataType }),
      ...(runtime.manifest.x402.catalog ? { schema: resource.schema, provenance: resource.provenance } : {}),
      offers: definition.offers.map((candidate) => ({
        id: candidate.id,
        payment: {
          scheme: runtime.manifest.x402.scheme,
          network: runtime.manifest.x402.network,
          asset: runtime.manifest.x402.asset,
          amount: candidate.amount,
          payTo: auth.env.facilitatorAddress,
          transferMethod: runtime.manifest.x402.assetTransferMethod,
        },
      })),
    };
  });
  return {
    operationId,
    readHandle: { kind: 'catalog', operationId },
    catalog,
    freeInspection: true,
    deliveryState: 'not_delivered',
  };
}

function offerResponse(runtime: ApplicationRuntime, auth: AuthorizedRequest, operationId: string, resourceId: string): Record<string, unknown> | null {
  const resourceDefinition = pinnedResource(runtime.manifest, resourceId);
  const resource = runtime.resources.get(resourceId);
  if (!resourceDefinition || !resource || resource.hash !== resourceDefinition.resourceSha256) return null;
  return {
    operationId,
    readHandle: { kind: 'offer', operationId },
    resourceId: resource.resourceId,
    resourceSha256: resource.hash,
    contentType: resource.contentType,
    ...(resourceDefinition.dataType === undefined ? {} : { dataType: resourceDefinition.dataType }),
    ...(runtime.manifest.x402.catalog ? { schema: resource.schema, provenance: resource.provenance } : {}),
    payment: {
      scheme: runtime.manifest.x402.scheme,
      network: runtime.manifest.x402.network,
      asset: runtime.manifest.x402.asset,
      amount: resourceDefinition.offers[0]!.amount,
      payTo: auth.env.facilitatorAddress,
      transferMethod: runtime.manifest.x402.assetTransferMethod,
    },
    offers: resourceDefinition.offers.map((candidate) => ({
      id: candidate.id,
      payment: {
        scheme: runtime.manifest.x402.scheme,
        network: runtime.manifest.x402.network,
        asset: runtime.manifest.x402.asset,
        amount: candidate.amount,
        payTo: auth.env.facilitatorAddress,
        transferMethod: runtime.manifest.x402.assetTransferMethod,
      },
    })),
    freeInspection: true,
    deliveryState: 'not_delivered',
  };
}

async function verifiedInspectionRead(
  runtime: ApplicationRuntime,
  auth: AuthorizedRequest,
  handle: { kind: 'catalog' | 'offer'; operationId: string },
  resourceId: string,
): Promise<boolean> {
  const expectedRequest = handle.kind === 'catalog'
    ? requestHash({ method: 'GET', path: '/catalog' })
    : requestHash({ method: 'GET', path: '/offer', resourceId });
  const response = handle.kind === 'catalog'
    ? catalogResponse(runtime, auth, handle.operationId)
    : offerResponse(runtime, auth, handle.operationId, resourceId);
  if (!response) return false;
  return verifyInspectionRead(runtime.pool, {
    operationId: handle.operationId,
    envId: auth.envId,
    generationId: auth.generationId,
    participantId: auth.participantId,
    manifestSha256: runtime.loadedManifest.sha256,
    kind: handle.kind,
    expectedRequestSha256: expectedRequest,
    expectedResponseSha256: responseSha256(response),
  });
}

async function updateOperationStatus(runtime: ApplicationRuntime, auth: AuthorizedRequest, operationId: string, status: string, offerId: string, amount: string, resourceId: string, resourceSha256: string): Promise<boolean> {
  return withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => {
    return withTransaction(runtime.pool, async (client) => {
      const generation = await client.query(
        `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp() FOR UPDATE`,
        [auth.envId, auth.generationId],
      );
      if (!generation.rowCount) return false;
      const result = await client.query(
        `UPDATE bef_operation SET status=$4,
                verification_started_at=CASE WHEN $4='verifying' THEN COALESCE(verification_started_at,clock_timestamp()) ELSE verification_started_at END
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3
            AND selected_offer_id=$5 AND selected_amount_units=$6
            AND selected_resource_id=$7 AND selected_resource_sha256=$8
            AND status='awaiting_payment'
          RETURNING operation_id`,
        [operationId, auth.envId, auth.generationId, status, offerId, amount, resourceId, resourceSha256],
      );
      return Boolean(result.rowCount);
    });
  });
}

async function recordDenial(runtime: ApplicationRuntime, auth: AuthorizedRequest, operationId: string | null, route: string, reason: string, requestHash: string): Promise<void> {
  await runtime.pool.query(
    `INSERT INTO bef_denial(denial_id,env_id,generation_id,operation_id,route,reason_code,request_sha256)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [randomUUID(), auth.envId, auth.generationId, operationId, route, reason, requestHash],
  );
}

function requestHash(value: unknown): string {
  return sha256(JSON.stringify(value));
}

function responseOperationId(reply: FastifyReply, operationId: string): FastifyReply {
  reply.header('X-BEF-Operation-Id', operationId);
  return reply;
}
async function reconcilePaymentResponse(
  runtime: ApplicationRuntime,
  auth: AuthorizedRequest,
  operationId: string,
  expectedMode: PaymentResponseMode,
  purpose: 'receipt' | 'delivery',
): Promise<Record<string, unknown> | null> {
  if ((expectedMode === 'combined' || purpose === 'delivery') && auth.resourceVariant !== 'canonical') return null;
  return withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
    const selected = await client.query<{
      operation_kind: string;
      operation_status: string;
      payment_response_mode: PaymentResponseMode;
      operation_response_sha256: string | null;
      operation_participant_id: string;
      generation_participant_id: string;
      generation_status: string;
      generation_manifest_sha256: string;
      original_requirements_pay_to: string | null;
      operation_receipt_status: string;
      selected_offer_id: string | null;
      selected_amount_units: string | null;
      selected_resource_id: string | null;
      selected_resource_sha256: string | null;
      operation_authorization_sha256: string | null;
      operation_transaction_hash: string | null;
      resource_variant: string;
      generation_payer_address: string;
      payment_authorization_sha256: string;
      payer_address: string | null;
      network: string;
      asset_address: string;
      amount_units: string;
      facilitator_address: string | null;
      payment_transaction_hash: string | null;
      payment_receipt_status: string;
      token_delta_units: string | null;
      payer_balance_before: string | null;
      payer_balance_after: string | null;
      facilitator_balance_before: string | null;
      facilitator_balance_after: string | null;
    }>(
      `SELECT o.operation_kind,o.status AS operation_status,o.receipt_status AS operation_receipt_status,
              o.payment_response_mode,
              o.response_sha256 AS operation_response_sha256,
              o.authorization_sha256 AS operation_authorization_sha256,o.transaction_hash AS operation_transaction_hash,
              o.selected_offer_id,o.selected_amount_units::text,o.selected_resource_id,o.selected_resource_sha256,
              o.participant_id AS operation_participant_id,g.participant_id AS generation_participant_id,
              g.status AS generation_status,g.manifest_sha256 AS generation_manifest_sha256,
              g.resource_variant,g.payer_address AS generation_payer_address,
              p.authorization_sha256 AS payment_authorization_sha256,p.payer_address,p.network,p.asset_address,
              (SELECT x.safe_request #>> '{paymentRequirements,payTo}' FROM bef_x402_observation x WHERE x.operation_id=o.operation_id AND x.phase='settle' ORDER BY x.observed_at ASC LIMIT 1) AS original_requirements_pay_to,
              p.amount_units,p.facilitator_address,p.transaction_hash AS payment_transaction_hash,
              p.receipt_status AS payment_receipt_status,p.token_delta_units,p.payer_balance_before,p.payer_balance_after,
              p.facilitator_balance_before,p.facilitator_balance_after
         FROM bef_operation o
         JOIN bef_generation g USING(env_id,generation_id)
         JOIN bef_payment p USING(operation_id,env_id,generation_id)
        WHERE o.operation_id=$1 AND o.env_id=$2 AND o.generation_id=$3 AND g.status='active' AND g.expires_at>clock_timestamp()
          AND g.manifest_sha256=$4 AND o.payment_response_mode=$5
        FOR UPDATE OF o,g,p`,
      [operationId, auth.envId, auth.generationId, runtime.loadedManifest.sha256, expectedMode],
    );
    const proof = selected.rows[0];
    if (!proof || proof.operation_kind !== 'purchase' || proof.resource_variant !== auth.resourceVariant
      || proof.operation_participant_id !== auth.participantId || proof.generation_participant_id !== auth.participantId) return null;
    if (expectedMode === 'deferred_delivery' && (proof.selected_offer_id === null || proof.selected_amount_units === null
      || proof.selected_resource_id === null || proof.selected_resource_sha256 === null)) return null;
    const resourceId = proof.selected_resource_id ?? runtime.manifest.x402.resourceId;
    const resource = runtime.resources.get(resourceId);
    if (!resource || (proof.selected_resource_sha256 !== null && proof.selected_resource_sha256 !== resource.hash)) return null;
    const responseBody = {
      operationId, resourceId: resource.resourceId, contentType: resource.contentType,
      contentHash: resource.hash, contentBytes: resource.bytes.toString('base64'), content: resource.parsed,
    };
    const responseHash = sha256(Buffer.from(JSON.stringify(responseBody)));
    const existing = await client.query<{ content_sha256: string; content_bytes: string; resource_id: string }>(
      'SELECT content_sha256,content_bytes,resource_id FROM bef_delivery WHERE operation_id=$1 FOR UPDATE', [operationId],
    );
    if (existing.rows.length > 1 || !['settled', 'delivered'].includes(proof.operation_status)) return null;
    const transactionHash = proof.operation_transaction_hash;
    const selectedAmount = proof.selected_amount_units ?? runtime.manifest.x402.amount;
    const selectedOfferPair = selectedPinnedResourceOffer(runtime.manifest, {
      resourceId, offerId: proof.selected_offer_id ?? 'canonical',
    });
    if (!selectedOfferPair || selectedOfferPair.offer.amount !== selectedAmount) return null;
    const amount = BigInt(selectedAmount);
    let exactBalances = false;
    try {
      exactBalances = proof.payer_balance_before !== null && proof.payer_balance_after !== null
        && proof.facilitator_balance_before !== null && proof.facilitator_balance_after !== null
        && BigInt(proof.payer_balance_before) - BigInt(proof.payer_balance_after) === amount
        && BigInt(proof.facilitator_balance_after) - BigInt(proof.facilitator_balance_before) === amount;
    } catch { exactBalances = false; }
    const valid = proof.operation_receipt_status === 'success' && proof.payment_receipt_status === 'success'
      && typeof transactionHash === 'string' && /^0x[0-9a-f]{64}$/i.test(transactionHash)
      && proof.payment_transaction_hash?.toLowerCase() === transactionHash.toLowerCase()
      && typeof proof.operation_authorization_sha256 === 'string'
      && /^[0-9a-f]{64}$/i.test(proof.operation_authorization_sha256)
      && proof.operation_authorization_sha256.toLowerCase() === proof.payment_authorization_sha256.toLowerCase()
      && proof.generation_payer_address.toLowerCase() === auth.payerAddress.toLowerCase()
      && proof.payer_address?.toLowerCase() === auth.payerAddress.toLowerCase()
      && typeof proof.facilitator_address === 'string' && /^0x[0-9a-f]{40}$/i.test(proof.facilitator_address)
      && typeof proof.original_requirements_pay_to === 'string' && /^0x[0-9a-f]{40}$/i.test(proof.original_requirements_pay_to)
      && proof.facilitator_address.toLowerCase() === proof.original_requirements_pay_to.toLowerCase()
      && proof.network === runtime.manifest.x402.network
      && proof.asset_address.toLowerCase() === runtime.manifest.x402.asset.toLowerCase()
      && proof.amount_units === selectedAmount
      && proof.token_delta_units === selectedAmount && exactBalances;
    if (!valid) return null;
    const receiptBody = paidReceipt({
      operationId,
      transactionHash: transactionHash!,
      amount: selectedAmount,
      asset: proof.asset_address,
      network: proof.network,
      payTo: proof.facilitator_address!,
    });
    if (expectedMode === 'deferred_delivery'
      && proof.operation_response_sha256?.trim().toLowerCase() !== responseSha256(receiptBody)) return null;
    if (purpose === 'receipt') {
      if (expectedMode !== 'deferred_delivery' || (proof.operation_status === 'settled' && existing.rowCount !== 0)
        || (proof.operation_status === 'delivered' && (existing.rowCount !== 1 || existing.rows[0]?.content_sha256 !== resource.hash
          || Number(existing.rows[0]?.content_bytes) !== resource.bytes.byteLength || existing.rows[0]?.resource_id !== resource.resourceId))) return null;
      return receiptBody;
    }
    if (proof.operation_status === 'delivered') {
      return existing.rowCount === 1 && existing.rows[0]?.content_sha256 === resource.hash
        && Number(existing.rows[0]?.content_bytes) === resource.bytes.byteLength && existing.rows[0]?.resource_id === resource.resourceId ? responseBody : null;
    }
    if (proof.operation_status !== 'settled' || existing.rowCount !== 0) return null;
    if (existing.rowCount === 0) {
      await client.query(
        `INSERT INTO bef_delivery(delivery_id,operation_id,resource_id,content_sha256,content_bytes)
         VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_id) DO NOTHING`,
        [randomUUID(), operationId, resource.resourceId, resource.hash, resource.bytes.byteLength],
      );
    }
    const delivery = await client.query<{ content_sha256: string; content_bytes: string; resource_id: string }>(
      'SELECT content_sha256,content_bytes,resource_id FROM bef_delivery WHERE operation_id=$1', [operationId],
    );
    if (delivery.rowCount !== 1 || delivery.rows[0]?.content_sha256 !== resource.hash
      || Number(delivery.rows[0]?.content_bytes) !== resource.bytes.byteLength || delivery.rows[0]?.resource_id !== resource.resourceId) return null;
    const updated = await client.query(
      `UPDATE bef_operation SET status='delivered',
              response_sha256=CASE WHEN payment_response_mode='combined' THEN $4 ELSE response_sha256 END,
              completed_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='settled'
          AND transaction_hash=$5 AND receipt_status='success' RETURNING operation_id`,
      [operationId, auth.envId, auth.generationId, responseHash, transactionHash],
    );
    if (updated.rowCount !== 1) return null;
    return responseBody;
  }));
}

function sendProtocolResponse(reply: FastifyReply, response: { status: number; headers: Record<string, string>; body?: unknown }, operationId: string) {
  for (const [name, value] of Object.entries(response.headers)) reply.header(name, value);
  responseOperationId(reply, operationId);
  return reply.code(response.status).send(response.body ?? null);
}

async function verifyActiveOperation(runtime: ApplicationRuntime, auth: AuthorizedRequest, operationId: string): Promise<boolean> {
  const result = await runtime.pool.query(
    `SELECT 1 FROM bef_generation g JOIN bef_operation o USING(env_id,generation_id)
      WHERE g.env_id=$1 AND g.generation_id=$2 AND g.status='active' AND g.expires_at>clock_timestamp()
        AND o.operation_id=$3 AND o.status IN ('awaiting_payment','verifying')`,
    [auth.envId, auth.generationId, operationId],
  );
  return Boolean(result.rowCount);
}

function participantToolPath(request: FastifyRequest): string {
  return request.url.split('?', 1)[0] ?? request.url;
}

function paymentPayer(value: unknown): string | null {
  if (!isRecord(value) || !isRecord(value.payload)) return null;
  const authorization = value.payload.authorization;
  if (!isRecord(authorization) || typeof authorization.from !== 'string') return null;
  return /^0x[0-9a-f]{40}$/i.test(authorization.from) ? authorization.from.toLowerCase() : null;
}

export async function registerToolRoutes(
  app: FastifyInstance,
  runtime: ApplicationRuntime,
  protocols: Map<string, PaymentProtocol>,
): Promise<void> {
  app.get('/tools/:envId/catalog', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const operation = await operationForRequest(runtime, auth, {
      requestHash: requestHash({ method: 'GET', path: '/catalog' }), kind: 'catalog',
    });
    const response = catalogResponse(runtime, auth, operation.operationId);
    const accepted = await withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
      const generation = await client.query(
        `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp() FOR UPDATE`,
        [auth.envId, auth.generationId],
      );
      if (!generation.rowCount) return false;
      const updated = await client.query(
        `UPDATE bef_operation SET operation_kind='catalog',status='accepted',receipt_status='not_submitted',response_sha256=$4
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND operation_kind='catalog'
            AND status IN ('awaiting_payment','accepted') RETURNING operation_id`,
        [operation.operationId, auth.envId, auth.generationId, responseSha256(response)],
      );
      return Boolean(updated.rowCount);
    }));
    if (!accepted) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'generation_fenced' });
    return responseOperationId(reply, operation.operationId).send(response);
  });

  app.get('/tools/:envId/offer', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const query = request.query as { resourceId?: unknown };
    const resourceId = resolveOfferResourceId(runtime.manifest, query.resourceId);
    const resourceDefinition = pinnedResource(runtime.manifest, resourceId);
    const resource = typeof resourceId === 'string' ? runtime.resources.get(resourceId) : undefined;
    if (typeof resourceId !== 'string' || !resourceDefinition || !resource || resource.hash !== resourceDefinition.resourceSha256) return reply.code(400).send({ error: 'unknown_resource' });
    const operation = await operationForRequest(runtime, auth, {
      requestHash: requestHash({ method: 'GET', path: '/offer', resourceId }), kind: 'offer',
    });
    const offer = offerResponse(runtime, auth, operation.operationId, resourceId);
    if (!offer) return responseOperationId(reply, operation.operationId).code(503).send({ error: 'pinned_resource_unavailable' });
    const accepted = await withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
      const generation = await client.query(
        `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp() FOR UPDATE`,
        [auth.envId, auth.generationId],
      );
      if (!generation.rowCount) return false;
      const updated = await client.query(
        `UPDATE bef_operation SET operation_kind='offer',status='accepted',receipt_status='not_submitted',response_sha256=$4
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND operation_kind='offer' AND status IN ('awaiting_payment','accepted')
          RETURNING operation_id`,
        [operation.operationId, auth.envId, auth.generationId, responseSha256(offer)],
      );
      return Boolean(updated.rowCount);
    }));
    if (!accepted) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'generation_fenced' });
    return responseOperationId(reply, operation.operationId).send(offer);
  });

  app.get('/tools/:envId/retrieve', async (request, reply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const parsed = RetrieveQuerySchema.safeParse(request.query);
    if (!parsed.success) return reply.code(400).send({ error: 'invalid_retrieve_request' });
    const delivered = await reconcilePaymentResponse(runtime, auth, parsed.data.operationId, 'deferred_delivery', 'delivery');
    if (!delivered) return responseOperationId(reply, parsed.data.operationId).code(409).send({ error: 'delivery_unavailable_or_unverified' });
    return responseOperationId(reply, parsed.data.operationId).send(delivered);
  });

  const paymentHandler = (paymentResponseMode: PaymentResponseMode) => async (request: FastifyRequest, reply: FastifyReply) => {
    const auth = await authorizeParticipant(runtime, request, reply);
    if (!auth) return;
    const body = request.body as unknown;
    let readRequest: ReturnType<typeof PayRequestSchema.parse> | null = null;
    if (paymentResponseMode === 'combined') {
      if (!isRecord(body) || Object.keys(body).some((key) => key !== 'resourceId' && key !== 'offerId')) {
        return reply.code(400).send({ error: 'invalid_purchase_request' });
      }
    } else {
      const parsed = PayRequestSchema.safeParse(body);
      if (!parsed.success) return reply.code(400).send({ error: 'invalid_pay_request' });
      readRequest = parsed.data;
    }
    const selected = selectedPinnedResourceOffer(runtime.manifest, body);
    if (!selected) return reply.code(400).send({ error: 'unknown_resource_or_offer' });
    if (readRequest) {
      if (!(await verifiedInspectionRead(runtime, auth, readRequest.readHandle, selected.resource.resourceId))) {
        return reply.code(409).send({ error: 'inspection_handle_invalid' });
      }
      if (!sameAcceptedPaymentTerms(readRequest.acceptedTerms, expectedPaymentTerms(runtime, auth, selected))) {
        return reply.code(409).send({ error: 'accepted_payment_terms_mismatch' });
      }
    }
    const selectedOffer = selected.offer;
    const selectedResourceDefinition = selected.resource;
    const selectedResource = runtime.resources.get(selectedResourceDefinition.resourceId);
    if (!selectedResource || selectedResource.hash !== selectedResourceDefinition.resourceSha256) {
      return reply.code(503).send({ error: 'pinned_resource_unavailable' });
    }
    const path = participantToolPath(request);
    const logicalRequest = { method: 'POST', path, body };
    let operation: Operation;
    try {
      operation = await operationForRequest(runtime, auth, {
        requestHash: requestHash(logicalRequest), kind: 'purchase', paymentResponseMode,
      });
    } catch (error) {
      if (error instanceof Error && (error.message === 'idempotency_key_reused_for_different_request'
        || error.message === 'payment_response_mode_conflict')) {
        return reply.code(409).send({ error: 'idempotency_key_conflict' });
      }
      throw error;
    }
    const paymentHeader = safeString(request.headers['payment-signature']) ?? safeString(request.headers['x-payment']);
    const selectionPersisted = await withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
      const generation = await client.query(
        `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status='active' AND expires_at>clock_timestamp() FOR UPDATE`,
        [auth.envId, auth.generationId],
      );
      if (!generation.rowCount) return false;
      const existing = await client.query<{
        status: string;
        selected_offer_id: string | null;
        selected_amount_units: string | null;
        selected_resource_id: string | null;
        selected_resource_sha256: string | null;
        offer_selected_at: Date | string | null;
        verification_started_at: Date | string | null;
        offer_selection_eligible: boolean;
      }>(
        `SELECT status,selected_offer_id,selected_amount_units::text,selected_resource_id,selected_resource_sha256,offer_selected_at,
                verification_started_at,offer_selection_eligible
           FROM bef_operation
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 FOR UPDATE`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      const prior = existing.rows[0];
      if (!prior) return false;
      if (prior.selected_offer_id !== null) {
        return prior.selected_offer_id === selectedOffer.id
          && prior.selected_amount_units === selectedOffer.amount
          && prior.selected_resource_id === selectedResource.resourceId
          && prior.selected_resource_sha256 === selectedResource.hash
          && prior.offer_selected_at !== null;
      }
      if (prior.selected_amount_units !== null || prior.selected_resource_id !== null || prior.selected_resource_sha256 !== null || prior.offer_selected_at !== null
        || prior.verification_started_at !== null || prior.status !== 'awaiting_payment'
        || prior.offer_selection_eligible !== true) return false;
      const persisted = await client.query(
        `UPDATE bef_operation SET selected_offer_id=$4,selected_amount_units=$5,
                selected_resource_id=$6,selected_resource_sha256=$7,
                offer_selected_at=clock_timestamp(),offer_selection_eligible=false
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND operation_kind='purchase'
            AND status='awaiting_payment' AND offer_selection_eligible=true
            AND selected_offer_id IS NULL AND selected_amount_units IS NULL
            AND selected_resource_id IS NULL AND selected_resource_sha256 IS NULL
            AND offer_selected_at IS NULL AND verification_started_at IS NULL
          RETURNING operation_id`,
        [operation.operationId, auth.envId, auth.generationId, selectedOffer.id, selectedOffer.amount, selectedResource.resourceId, selectedResource.hash],
      );
      return Boolean(persisted.rowCount);
    }));
    if (!selectionPersisted) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'offer_selection_conflict' });
    if (operation.status === 'delivered') {
      if (paymentResponseMode === 'deferred_delivery') {
        const receipt = await reconcilePaymentResponse(runtime, auth, operation.operationId, 'deferred_delivery', 'receipt');
        if (!receipt) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'settlement_reconciliation_required', operationId: operation.operationId });
        return responseOperationId(reply, operation.operationId).send(receipt);
      }
      if (auth.resourceVariant !== 'canonical') return responseOperationId(reply, operation.operationId).code(409).send({ error: 'resource_variant_delivery_conflict' });
      const delivery = await runtime.pool.query<{ content_sha256: string; content_bytes: string; resource_id: string }>(
        `SELECT content_sha256,content_bytes,resource_id FROM bef_delivery WHERE operation_id=$1`, [operation.operationId],
      );
      if (!delivery.rowCount || delivery.rows[0]?.content_sha256 !== selectedResource.hash
        || Number(delivery.rows[0]?.content_bytes) !== selectedResource.bytes.byteLength
        || delivery.rows[0]?.resource_id !== selectedResource.resourceId) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'delivery_reconciliation_required' });
      const responseBody = {
        operationId: operation.operationId, resourceId: selectedResource.resourceId,
        contentType: selectedResource.contentType, contentHash: selectedResource.hash,
        contentBytes: selectedResource.bytes.toString('base64'), content: selectedResource.parsed,
      };
      return responseOperationId(reply, operation.operationId).send(responseBody);
    }
    if (operation.status === 'settled') {
      if (paymentResponseMode === 'deferred_delivery') {
        const receipt = await reconcilePaymentResponse(runtime, auth, operation.operationId, 'deferred_delivery', 'receipt');
        if (!receipt) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'settlement_reconciliation_required', operationId: operation.operationId });
        return responseOperationId(reply, operation.operationId).send(receipt);
      }
      if (auth.resourceVariant === 'mismatched_data') {
        const selectedResourceMismatch = mismatchedResource(selectedResource);
        return responseOperationId(reply, operation.operationId).code(409).send({
          error: 'resource_content_hash_mismatch', operationId: operation.operationId,
          claimedSha256: selectedResource.hash, actualDataSha256: selectedResourceMismatch.hash,
          resourceEvidencePath: `admin:/internal/admin/environments/${auth.envId}/resource-candidate?generationId=${auth.generationId}`,
        });
      }
      const recovered = await reconcilePaymentResponse(runtime, auth, operation.operationId, 'combined', 'delivery');
      if (!recovered) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'settlement_reconciliation_required', operationId: operation.operationId });
      return responseOperationId(reply, operation.operationId).send(recovered);
    }
    if (operation.status === 'settling' || operation.status === 'settlement_unknown' || operation.status === 'reverted') {
      return responseOperationId(reply, operation.operationId).code(409).send({ error: 'settlement_outcome_unknown', operationId: operation.operationId });
    }
    const protocol = protocols.get(auth.envId);
    if (!protocol) return reply.code(503).send({ error: 'payment_protocol_unavailable' });
    const stillActive = await verifyActiveOperation(runtime, auth, operation.operationId);
    if (!stillActive) return responseOperationId(reply, operation.operationId).code(409).send({ error: 'generation_fenced' });
    if (paymentHeader && !(await updateOperationStatus(runtime, auth, operation.operationId, 'verifying', selectedOffer.id, selectedOffer.amount,
      selectedResource.resourceId, selectedResource.hash))) {
      return responseOperationId(reply, operation.operationId).code(409).send({ error: 'generation_fenced' });
    }
    const adapter = new FastifyAdapter(request);
    const context = { adapter, path, method: 'POST', ...(paymentHeader ? { paymentHeader } : {}) };
    const scope = {
      operationId: operation.operationId,
      generationId: auth.generationId,
      requestSha256: operation.requestHash,
      variantId: auth.resourceVariant === 'canonical' ? 'baseline' : auth.resourceVariant,
    };
    const protocolResult = await facilitatorRequestScope.run(scope, () => protocol.http.processHTTPRequest(context));
    if (protocolResult.type === 'payment-error') {
      if (paymentHeader) {
        await runtime.pool.query(
          `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='verifying'`,
          [operation.operationId, auth.envId, auth.generationId],
        );
        await recordDenial(runtime, auth, operation.operationId, path, 'payment_protocol_rejected', requestHash({ resourceId: selectedResource.resourceId, paymentHeaderPresent: true }));
      } else {
        await runtime.pool.query(
          `UPDATE bef_operation SET status='awaiting_payment',receipt_status='not_submitted' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='verifying'`,
          [operation.operationId, auth.envId, auth.generationId],
        );
      }
      const response = protocolResult.response;
      return sendProtocolResponse(reply, response, operation.operationId);
    }
    if (protocolResult.type !== 'payment-verified') {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      return responseOperationId(reply, operation.operationId).code(403).send({ error: 'payment_route_not_protected' });
    }

    const signedPayer = paymentPayer(protocolResult.paymentPayload);
    if (!signedPayer || signedPayer !== auth.payerAddress.toLowerCase()) {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      await recordDenial(runtime, auth, operation.operationId, path, 'payment_payer_outside_generation', requestHash({ expectedPayer: auth.payerAddress.toLowerCase(), actualPayer: signedPayer }));
      return responseOperationId(reply, operation.operationId).code(403).send({ error: 'payment_payer_outside_generation', operationId: operation.operationId });
    }

    const payer = auth.payerAddress;
    const token = runtime.manifest.contracts.usdc.address as Address;
    const payTo = auth.env.facilitatorAddress;
    if (!pinnedOfferRequirementsMatch({
      scheme: runtime.manifest.x402.scheme,
      network: runtime.manifest.x402.network,
      asset: runtime.manifest.x402.asset,
      amount: selectedOffer.amount,
      payTo,
    }, protocolResult.paymentRequirements)) {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='verifying'`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      return responseOperationId(reply, operation.operationId).code(409).send({ error: 'selected_offer_requirements_mismatch' });
    }
    const amount = BigInt(protocolResult.paymentRequirements.amount);

    const publicClient = createPublicClient({ chain: base, transport: http(auth.env.observerRpcUrl, { timeout: 15_000, retryCount: 0 }) });
    const payerBefore = await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payer] });
    const payToBefore = await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payTo] });
    const resource = auth.resourceVariant === 'mismatched_data' ? mismatchedResource(selectedResource) : selectedResource;
    const resourceResponse = paymentResponseMode === 'combined' ? {
      operationId: operation.operationId,
      resourceId: selectedResource.resourceId,
      contentType: selectedResource.contentType,
      contentHash: resource.hash,
      contentBytes: resource.bytes.toString('base64'),
      content: resource.parsed,
    } : null;
    let settlement: Awaited<ReturnType<PaymentProtocol['http']['processSettlement']>>;
    try {
      settlement = await facilitatorRequestScope.run(scope, () => protocol.http.processSettlement(
        protocolResult.paymentPayload,
        protocolResult.paymentRequirements,
        protocolResult.declaredExtensions,
        {
          request: context,
          responseBody: paymentResponseMode === 'combined' ? resource.bytes : Buffer.alloc(0),
          responseHeaders: { 'content-type': paymentResponseMode === 'combined' ? selectedResource.contentType : 'application/json' },
        },
        undefined,
        protocolResult.beforeHandlerSettlement,
        'after-handler',
      ));
    } catch {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status IN ('verifying','settling','settlement_unknown')`,
        [operation.operationId, auth.envId, auth.generationId],
      ).catch(() => undefined);
      return responseOperationId(reply, operation.operationId).code(502).send({ error: 'settlement_outcome_unknown', operationId: operation.operationId });
    }
    if (!settlement.success || typeof settlement.transaction !== 'string' || !/^0x[0-9a-f]{64}$/i.test(settlement.transaction)) {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status IN ('verifying','settling','settlement_unknown')`,
        [operation.operationId, auth.envId, auth.generationId],
      );
      return responseOperationId(reply, operation.operationId).code(502).send({ error: 'settlement_outcome_unknown', operationId: operation.operationId });
    }
    const transactionHash = settlement.transaction as Hex;
    const receiptBody = paidReceipt({
      operationId: operation.operationId,
      transactionHash,
      amount: amount.toString(),
      asset: runtime.manifest.x402.asset,
      network: runtime.manifest.x402.network,
      payTo,
    });
    await runtime.pool.query(
      `UPDATE bef_operation SET transaction_hash=COALESCE(transaction_hash,$4),status='settling',receipt_status='unknown'
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND (transaction_hash IS NULL OR transaction_hash=$4)`,
      [operation.operationId, auth.envId, auth.generationId, transactionHash],
    );
    try {
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash,
        confirmations: 1,
        timeout: runtime.manifest.x402.confirmationTimeoutMs,
        pollingInterval: 1_000,
      });
      if (receipt.status !== 'success') {
        await runtime.pool.query(
          `UPDATE bef_operation SET status='reverted',receipt_status='reverted',completed_at=clock_timestamp() WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
          [operation.operationId, auth.envId, auth.generationId],
        );
        await runtime.pool.query(
          `UPDATE bef_payment SET transaction_hash=$4,receipt_status='reverted',observed_at=clock_timestamp() WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
          [operation.operationId, auth.envId, auth.generationId, transactionHash],
        );
        return responseOperationId(reply, operation.operationId).code(502).send({ error: 'local_settlement_reverted', operationId: operation.operationId });
      }
      const transfer = receipt.logs.some((log) => {
        if (log.address.toLowerCase() !== token.toLowerCase()) return false;
        try {
          const event = decodeEventLog({ abi: resourceTransferAbi, eventName: 'Transfer', data: log.data, topics: log.topics }) as { args: unknown };
          const args = event.args as unknown as { from: Address; to: Address; value: bigint };
          return args.from.toLowerCase() === payer.toLowerCase() && args.to.toLowerCase() === payTo.toLowerCase()
            && args.value === amount;
        } catch { return false; }
      });
      const payerAfter = BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payer] }));
      const payToAfter = BigInt(await publicClient.readContract({ address: token, abi: balanceAbi, functionName: 'balanceOf', args: [payTo] }));
      if (!transfer || payerBefore - payerAfter !== amount || payToAfter - payToBefore !== amount) {
        await runtime.pool.query(
          `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown' WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status IN ('verifying','settling','settlement_unknown')`,
          [operation.operationId, auth.envId, auth.generationId],
        );
        return responseOperationId(reply, operation.operationId).code(502).send({ error: 'local_settlement_effect_unverified', operationId: operation.operationId });
      }
      if (resource.hash !== selectedResource.hash) {
        await withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
          const generation = await client.query(
            `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status IN ('active','fenced') FOR UPDATE`,
            [auth.envId, auth.generationId],
          );
          if (!generation.rowCount) throw new Error('generation_missing_after_settlement');
          const payment = await client.query(
            `UPDATE bef_payment SET transaction_hash=$4,receipt_status='success',token_delta_units=$5,
                 payer_balance_before=$6,payer_balance_after=$7,facilitator_balance_before=$8,facilitator_balance_after=$9,observed_at=clock_timestamp()
               WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 RETURNING payment_id`,
            [operation.operationId, auth.envId, auth.generationId, transactionHash, amount.toString(), payerBefore.toString(), payerAfter.toString(), payToBefore.toString(), payToAfter.toString()],
          );
          if (!payment.rowCount) throw new Error('payment_row_missing_after_settlement');
          await client.query(
            `INSERT INTO bef_denial(denial_id,env_id,generation_id,operation_id,route,reason_code,request_sha256)
             VALUES($1,$2,$3,$4,$5,$6,$7)`,
            [randomUUID(), auth.envId, auth.generationId, operation.operationId, path, 'resource_content_hash_mismatch',
              requestHash({ claimedSha256: selectedResource.hash, actualDataSha256: resource.hash })],
          );
          const completed = await client.query(
            `UPDATE bef_operation SET transaction_hash=$4,status='settled',receipt_status='success',
                    response_sha256=CASE WHEN payment_response_mode='deferred_delivery' THEN $5 ELSE response_sha256 END,
                    completed_at=clock_timestamp()
              WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='settling' AND transaction_hash=$4
              RETURNING operation_id`,
            [operation.operationId, auth.envId, auth.generationId, transactionHash, responseSha256(receiptBody)],
          );
          if (!completed.rowCount) throw new Error('operation_terminal_state_conflict');
        }));
        if (paymentResponseMode === 'deferred_delivery') {
          for (const [name, value] of Object.entries(settlement.headers)) reply.header(name, value);
          return responseOperationId(reply, operation.operationId).send(receiptBody);
        }
        return responseOperationId(reply, operation.operationId).code(409).send({
          error: 'resource_content_hash_mismatch', operationId: operation.operationId,
          claimedSha256: selectedResource.hash, actualDataSha256: resource.hash,
          resourceEvidencePath: `admin:/internal/admin/environments/${auth.envId}/resource-candidate?generationId=${auth.generationId}`,
        });
      }
      const responseBody = paymentResponseMode === 'combined' ? resourceResponse : receiptBody;
      const responseHash = responseSha256(responseBody);
      await withEnvironmentAdvisoryLock(runtime.pool, auth.envId, async () => withTransaction(runtime.pool, async (client) => {
        const generation = await client.query(
          `SELECT 1 FROM bef_generation WHERE env_id=$1 AND generation_id=$2 AND status IN ('active','fenced') FOR UPDATE`,
          [auth.envId, auth.generationId],
        );
        if (!generation.rowCount) throw new Error('generation_missing_after_settlement');
        const payment = await client.query(
          `UPDATE bef_payment SET transaction_hash=$4,receipt_status='success',token_delta_units=$5,
               payer_balance_before=$6,payer_balance_after=$7,facilitator_balance_before=$8,facilitator_balance_after=$9,observed_at=clock_timestamp()
             WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 RETURNING payment_id`,
          [operation.operationId, auth.envId, auth.generationId, transactionHash, amount.toString(), payerBefore.toString(), payerAfter.toString(), payToBefore.toString(), payToAfter.toString()],
        );
        if (!payment.rowCount) throw new Error('payment_row_missing_after_settlement');
        if (paymentResponseMode === 'combined') {
          await client.query(
            `INSERT INTO bef_delivery(delivery_id,operation_id,resource_id,content_sha256,content_bytes)
               VALUES($1,$2,$3,$4,$5) ON CONFLICT(operation_id) DO NOTHING`,
            [randomUUID(), operation.operationId, selectedResource.resourceId, resource.hash, resource.bytes.byteLength],
          );
        }
        const delivered = await client.query(
          `UPDATE bef_operation SET transaction_hash=$3,
                  status=CASE WHEN payment_response_mode='deferred_delivery' THEN 'settled' ELSE 'delivered' END,
                  receipt_status='success',response_sha256=$2,completed_at=clock_timestamp()
             WHERE operation_id=$1 AND env_id=$4 AND generation_id=$5 AND status='settling' AND transaction_hash=$3
             RETURNING operation_id`,
          [operation.operationId, responseHash, transactionHash, auth.envId, auth.generationId],
        );
        if (!delivered.rowCount) throw new Error('operation_terminal_state_conflict');
      }));
      for (const [name, value] of Object.entries(settlement.headers)) reply.header(name, value);
      return responseOperationId(reply, operation.operationId).send(responseBody);
    } catch {
      await runtime.pool.query(
        `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown',transaction_hash=COALESCE(transaction_hash,$4)
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND status IN ('verifying','settling','settlement_unknown')`,
        [operation.operationId, auth.envId, auth.generationId, transactionHash],
      ).catch(() => undefined);
      return responseOperationId(reply, operation.operationId).code(502).send({ error: 'settlement_observation_unknown', operationId: operation.operationId });
    }
  };
  app.post('/tools/:envId/purchase', paymentHandler('combined'));
  app.post('/tools/:envId/pay', paymentHandler('deferred_delivery'));
}
