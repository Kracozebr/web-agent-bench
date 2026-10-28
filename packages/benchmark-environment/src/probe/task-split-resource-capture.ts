/**
 * Participant-facing capture helpers for the separate pay/retrieve protocol.
 * These helpers produce evidence for observed local-fork behavior only; they
 * do not promote a benchmark result or claim live-chain acceptance.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { PaymentRequired, PaymentRequirements } from '@x402/core/types';
import type { RuntimeManifest } from '../manifest.js';
import { loadPinnedResources } from '../resource.js';
import { apiPath } from './environment.js';
import { sha256Bytes } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { readCaseDatabaseFacts } from './task-reference-case-drivers.js';
import {
  projectPinnedPublicCatalog,
  type PublicCatalogProjection,
} from './task-reference-catalog-objectives.js';
import { projectDeliveryEnvelope } from './task-reference-cases.js';
import { transferEvents } from './rpc.js';
import { createSignedPayload, readSettlementHeader } from './x402.js';

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type SplitActionKind = 'inspect_catalog' | 'inspect_offer' | 'pay' | 'retrieve';

/** The action trace deliberately carries only public operation and artifact references. */
export type SplitParticipantAction = {
  kind: SplitActionKind;
  operationId: string;
  rawResponsePath: string;
  rawResponseSha256: string;
};

export type SplitAcceptedTerms = {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  transferMethod: string;
};

export type SplitReadOffer = {
  resourceId: string;
  offerId: string;
  acceptedTerms: SplitAcceptedTerms;
};

/**
 * The handle object itself is intentionally the capability. A private WeakMap
 * witness prevents cloned, forged, cross-context, or cross-generation handles
 * from being accepted accidentally by this library. The authoritative proof
 * remains the participant HTTP response plus readonly PostgreSQL observations.
 */
export type SplitReadHandle = {
  kind: 'catalog' | 'offer';
  operationId: string;
  readHandle: { kind: 'catalog' | 'offer'; operationId: string };
  rawResponsePath: string;
  rawResponseSha256: string;
  participantAction: SplitParticipantAction;
  offers: readonly SplitReadOffer[];
  /** Present only for catalog reads; validated from the same actual participant response. */
  catalogProjection?: PublicCatalogProjection;
};

export type SplitResourceSelection = { resourceId: string; offerId: string };
export type SplitCaptureOptions = { variantId: string; label: string };

export type SplitPaymentCapture = {
  operationId: string;
  transactionHash: string;
  paymentReceipt: Record<string, unknown>;
  settlementReceipt: {
    blockNumber: string;
    blockHash: string;
    status: string;
    transactionHash: string;
  };
  envelope: Record<string, unknown>;
  deliveryProjection: ReturnType<typeof projectDeliveryEnvelope>;
  facilitatorGas: Record<string, unknown>;
  deliveryContentPath: string;
  deliveryContentSha256: string;
  participantActions: [SplitParticipantAction, SplitParticipantAction];
};

type SplitReadWitness = {
  context: ProbeContext;
  scope: string;
  kind: 'catalog' | 'offer';
  operationId: string;
  readHandle: { kind: 'catalog' | 'offer'; operationId: string };
  offers: Map<string, SplitReadOffer>;
  catalogProjection?: PublicCatalogProjection;
};

const readWitnesses = new WeakMap<object, SplitReadWitness>();

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function jsonSha256(value: unknown): string {
  return createHash('sha256').update(Buffer.from(JSON.stringify(value), 'utf8')).digest('hex');
}

/** Deferred delivery keeps the original payment-receipt response hash on the operation row. */
export function deferredPaymentReceiptHashMatches(storedResponseSha256: unknown, paymentReceiptBody: unknown): boolean {
  return typeof storedResponseSha256 === 'string' && /^[0-9a-f]{64}$/i.test(storedResponseSha256)
    && storedResponseSha256.toLowerCase() === jsonSha256(paymentReceiptBody);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_split_${label}_invalid`);
  return value;
}

function validAddress(value: unknown, label: string): string {
  const parsed = requiredString(value, label);
  if (!ADDRESS.test(parsed)) throw new Error(`task_split_${label}_invalid`);
  return parsed.toLowerCase();
}

function safeLabel(value: string): string {
  const label = value.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 96);
  if (!label) throw new Error('task_split_label_invalid');
  return label;
}

function scopeFor(session: GenerationSession): string {
  return [session.envId, session.generationId.toLowerCase(), session.participantId, session.payerAddress.toLowerCase()].join(':');
}

function assertSession(ctx: ProbeContext, session: GenerationSession): void {
  if (session.envId !== ctx.env.envId || !UUID.test(session.generationId)
    || session.signer.payerAddress.toLowerCase() !== session.payerAddress.toLowerCase()
    || !ADDRESS.test(session.payerAddress) || !/^[A-Za-z0-9_-]{32,128}$/.test(session.runToken)) {
    throw new Error('task_split_session_scope_invalid');
  }
  for (const secret of [session.runToken, session.signer.privateKey]) {
    if (!ctx.secretValues.includes(secret)) ctx.secretValues.push(secret);
  }
}

function participantHeaders(session: GenerationSession, idempotencyKey: string): Record<string, string> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'content-type': 'application/json',
    'Idempotency-Key': idempotencyKey,
  };
  return headers;
}

/** Delivery retrieval does not sign or pay again, but it still requires scoped route idempotency auth. */
export function buildSplitRetrieveHeaders(session: GenerationSession): Record<string, string> {
  return participantHeaders(session, randomUUID());
}

function facilitatorAddress(ctx: ProbeContext): string {
  const services = record(ctx.capability.services);
  const facilitator = record(services?.facilitator);
  return validAddress(facilitator?.address, 'facilitator_address');
}

function manifestResource(manifest: RuntimeManifest, resourceId: string) {
  const catalog = manifest.x402.catalog;
  const matches = catalog?.filter((entry) => entry.resourceId === resourceId) ?? [];
  if (matches.length !== 1) throw new Error('task_split_manifest_resource_missing');
  return matches[0]!;
}

function manifestOffer(manifest: RuntimeManifest, resourceId: string, offerId: string) {
  const resource = manifestResource(manifest, resourceId);
  const matches = resource.offers.filter((entry) => entry.id === offerId);
  if (matches.length !== 1) throw new Error('task_split_manifest_offer_missing');
  return { resource, offer: matches[0]! };
}

function observedTerms(value: unknown, manifest: RuntimeManifest, facilitator: string, amount: string): SplitAcceptedTerms {
  const payment = record(value);
  if (!payment || Object.keys(payment).sort().join(',') !== 'amount,asset,network,payTo,scheme,transferMethod'
    || payment.scheme !== manifest.x402.scheme || payment.network !== manifest.x402.network
    || String(payment.asset).toLowerCase() !== manifest.x402.asset.toLowerCase()
    || payment.amount !== amount || payment.transferMethod !== manifest.x402.assetTransferMethod
    || validAddress(payment.payTo, 'public_pay_to') !== facilitator) {
    throw new Error('task_split_public_payment_terms_manifest_mismatch');
  }
  return {
    scheme: requiredString(payment.scheme, 'scheme'),
    network: requiredString(payment.network, 'network'),
    asset: validAddress(payment.asset, 'asset'),
    amount: requiredString(payment.amount, 'amount'),
    payTo: validAddress(payment.payTo, 'pay_to'),
    transferMethod: requiredString(payment.transferMethod, 'transfer_method'),
  };
}

function freezeProjection<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) freezeProjection(child);
    Object.freeze(value);
  }
  return value;
}

function publicCatalogOffers(response: unknown, manifest: RuntimeManifest, facilitator: string): {
  offers: Map<string, SplitReadOffer>;
  projection: PublicCatalogProjection;
} {
  const projection = projectPinnedPublicCatalog({ response, manifest });
  if (projection.facilitatorAddress.toLowerCase() !== facilitator) {
    throw new Error('task_split_public_catalog_facilitator_mismatch');
  }
  const body = record(response)!;
  const offers = new Map<string, SplitReadOffer>();
  for (const rawResource of body.catalog as unknown[]) {
    const resource = record(rawResource)!;
    for (const rawOffer of resource.offers as unknown[]) {
      const offer = record(rawOffer)!;
      const offerId = requiredString(offer.id, 'public_offer_id');
      const key = `${requiredString(resource.resourceId, 'public_resource_id')}:${offerId}`;
      if (offers.has(key)) throw new Error('task_split_public_catalog_duplicate_offer');
      const pin = manifestOffer(manifest, resource.resourceId as string, offerId);
      offers.set(key, {
        resourceId: resource.resourceId as string,
        offerId,
        acceptedTerms: observedTerms(offer.payment, manifest, facilitator, pin.offer.amount),
      });
    }
  }
  return { offers, projection: freezeProjection(projection) };
}

/** Strictly project one public GET /offer response to the immutable manifest pins. */
export function projectSplitOfferRead(input: {
  response: unknown;
  manifest: RuntimeManifest;
  facilitatorAddress: string;
  resourceId: string;
}): SplitReadOffer[] {
  const body = record(input.response);
  const resource = manifestResource(input.manifest, input.resourceId);
  if (!body || body.resourceId !== resource.resourceId || body.resourceSha256 !== resource.resourceSha256
    || body.contentType !== resource.contentType || body.schema !== resource.schema
    || canonicalJson(body.provenance) !== canonicalJson(resource.provenance)
    || body.freeInspection !== true || body.deliveryState !== 'not_delivered') {
    throw new Error('task_split_public_offer_resource_manifest_mismatch');
  }
  if (resource.dataType === undefined ? Object.hasOwn(body, 'dataType') : body.dataType !== resource.dataType) {
    throw new Error('task_split_public_offer_data_type_mismatch');
  }
  if (!Array.isArray(body.offers) || body.offers.length !== resource.offers.length) {
    throw new Error('task_split_public_offer_list_mismatch');
  }
  const facilitator = validAddress(input.facilitatorAddress, 'facilitator_address');
  const result: SplitReadOffer[] = [];
  for (const [index, rawOffer] of body.offers.entries()) {
    const item = record(rawOffer);
    const pin = resource.offers[index];
    if (!item || !pin || item.id !== pin.id) throw new Error('task_split_public_offer_identity_mismatch');
    result.push({
      resourceId: resource.resourceId,
      offerId: pin.id,
      acceptedTerms: observedTerms(item.payment, input.manifest, facilitator, pin.amount),
    });
  }
  if (!result[0] || canonicalJson(observedTerms(body.payment, input.manifest, facilitator, resource.offers[0]!.amount))
    !== canonicalJson(result[0].acceptedTerms)) {
    throw new Error('task_split_public_offer_primary_terms_mismatch');
  }
  return result;
}

function assertReadIdentity(bodyValue: unknown, kind: 'catalog' | 'offer', responseOperationId: string | null): { operationId: string; readHandle: { kind: 'catalog' | 'offer'; operationId: string } } {
  const body = record(bodyValue);
  const handle = record(body?.readHandle);
  const operationId = requiredString(body?.operationId, 'read_operation_id');
  if (!UUID.test(operationId) || responseOperationId !== operationId || !handle
    || handle.kind !== kind || handle.operationId !== operationId) {
    throw new Error('task_split_public_read_handle_invalid');
  }
  return { operationId, readHandle: { kind, operationId } };
}

function assertOperationResponseHeader(headers: { get(name: string): string | null }, operationId: string): void {
  if (headers.get('x-bef-operation-id')?.toLowerCase() !== operationId.toLowerCase()) {
    throw new Error('task_split_operation_header_mismatch');
  }
}

function action(kind: SplitActionKind, operationId: string, rawResponsePath: string, rawResponseSha256: string): SplitParticipantAction {
  if (!UUID.test(operationId) || !HASH.test(rawResponseSha256)) throw new Error('task_split_action_identity_invalid');
  return { kind, operationId, rawResponsePath, rawResponseSha256: rawResponseSha256.toLowerCase() };
}

async function persistActualResponse(ctx: ProbeContext, operationId: string, kind: SplitActionKind, rawBody: Uint8Array): Promise<SplitParticipantAction> {
  const rawResponsePath = `task-split-resource/responses/${operationId}-${kind}.json`;
  await ctx.evidence.writeRawJson(rawResponsePath, rawBody, 'actual-tool-http');
  return action(kind, operationId, rawResponsePath, sha256Bytes(rawBody));
}

async function proveReadOperation(ctx: ProbeContext, session: GenerationSession, operationId: string, kind: 'catalog' | 'offer', resourceId: string | null, idempotencyKey: string, body: unknown, options: SplitCaptureOptions): Promise<void> {
  const expectedJsonHash = jsonSha256(body);
  const expectedRequestHash = jsonSha256(kind === 'catalog'
    ? { method: 'GET', path: '/catalog' }
    : { method: 'GET', path: '/offer', resourceId });
  const facts = await readCaseDatabaseFacts(ctx, session, `${safeLabel(options.label)}-${operationId}-read`, options.variantId);
  const matching = facts.operations.filter((row) => String(row.operation_id) === operationId);
  if (matching.length !== 1 || matching[0]!.operation_kind !== kind || matching[0]!.status !== 'accepted'
    || String(matching[0]!.response_sha256).toLowerCase() !== expectedJsonHash
    || facts.payments.some((row) => String(row.operation_id) === operationId)
    || facts.deliveries.some((row) => String(row.operation_id) === operationId)) {
    throw new Error('task_split_read_database_binding_mismatch');
  }
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId,
    variantId: options.variantId, label: `${safeLabel(options.label)}-${operationId}-read-proof`,
  });
  const generation = snapshot.generation.filter((row) => String(row.generation_id).toLowerCase() === session.generationId.toLowerCase());
  const rows = snapshot.operations.filter((row) => String(row.operation_id) === operationId);
  if (generation.length !== 1 || String(generation[0]!.participant_id) !== session.participantId
    || String(generation[0]!.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || generation[0]!.status !== 'active' || rows.length !== 1
    || String(rows[0]!.participant_id) !== session.participantId
    || String(rows[0]!.env_id) !== session.envId
    || String(rows[0]!.generation_id).toLowerCase() !== session.generationId.toLowerCase()
    || rows[0]!.operation_kind !== kind || rows[0]!.status !== 'accepted'
    || String(rows[0]!.request_sha256).toLowerCase() !== expectedRequestHash
    || String(rows[0]!.idempotency_key_sha256).toLowerCase() !== sha256Bytes(Buffer.from(idempotencyKey, 'utf8'))
    || String(rows[0]!.response_sha256).toLowerCase() !== expectedJsonHash
    || snapshot.payments.length !== 0 || snapshot.deliveries.length !== 0) {
    throw new Error('task_split_read_scope_proof_mismatch');
  }
}

async function inspectRead(ctx: ProbeContext, session: GenerationSession, kind: 'catalog' | 'offer', resourceId: string | null, options: SplitCaptureOptions): Promise<SplitReadHandle> {
  assertSession(ctx, session);
  const label = safeLabel(options.label);
  const idempotencyKey = randomUUID();
  const route = kind === 'catalog'
    ? `/tools/${session.envId}/catalog`
    : `/tools/${session.envId}/offer?resourceId=${encodeURIComponent(requiredString(resourceId, 'resource_id'))}`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-${kind}-read`, method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, route), headers: participantHeaders(session, idempotencyKey),
    operationId: null, variantId: options.variantId, includeRawResponseBytes: true,
    resolveOperationId: async (_status, body) => typeof record(body)?.operationId === 'string'
      ? String(record(body)!.operationId) : null,
  });
  if (response.status !== 200) throw new Error(`task_split_${kind}_inspection_failed_${response.status}`);
  const identity = assertReadIdentity(response.body, kind, response.operationId);
  assertOperationResponseHeader(response.headers, identity.operationId);
  const bytesJson = JSON.parse(response.rawBody.toString('utf8')) as unknown;
  if (canonicalJson(bytesJson) !== canonicalJson(response.body)) throw new Error('task_split_public_read_body_parse_mismatch');

  const facilitator = facilitatorAddress(ctx);
  const catalog = kind === 'catalog' ? publicCatalogOffers(response.body, ctx.runtime.manifest, facilitator) : null;
  const offers = catalog?.offers ?? new Map(projectSplitOfferRead({
      response: response.body, manifest: ctx.runtime.manifest,
      facilitatorAddress: facilitator, resourceId: resourceId!,
    }).map((offer) => [`${offer.resourceId}:${offer.offerId}`, offer]));
  await proveReadOperation(ctx, session, identity.operationId, kind, resourceId, idempotencyKey, response.body, options);
  const participantAction = await persistActualResponse(ctx, identity.operationId, kind === 'catalog' ? 'inspect_catalog' : 'inspect_offer', response.rawBody);
  const read: SplitReadHandle = Object.freeze({
    kind, operationId: identity.operationId, readHandle: Object.freeze(identity.readHandle),
    rawResponsePath: participantAction.rawResponsePath, rawResponseSha256: participantAction.rawResponseSha256,
    participantAction: Object.freeze(participantAction),
    offers: Object.freeze([...offers.values()].map((offer) => Object.freeze({ ...offer, acceptedTerms: Object.freeze({ ...offer.acceptedTerms }) }))),
    ...(catalog ? { catalogProjection: catalog.projection } : {}),
  });
  readWitnesses.set(read, {
    context: ctx, scope: scopeFor(session), kind, operationId: identity.operationId,
    readHandle: identity.readHandle, offers,
    ...(catalog ? { catalogProjection: catalog.projection } : {}),
  });
  return read;
}

/** Make one explicit participant GET /catalog; callers decide whether to reuse it. */
export async function inspectSplitCatalog(ctx: ProbeContext, session: GenerationSession, options: SplitCaptureOptions): Promise<SplitReadHandle> {
  return inspectRead(ctx, session, 'catalog', null, options);
}

/** Make one explicit participant GET /offer for the requested pinned resource. */
export async function inspectSplitOffer(ctx: ProbeContext, session: GenerationSession, resourceId: string, options: SplitCaptureOptions): Promise<SplitReadHandle> {
  return inspectRead(ctx, session, 'offer', resourceId, options);
}

function assertReadWitness(ctx: ProbeContext, session: GenerationSession, read: SplitReadHandle): SplitReadWitness {
  const witness = readWitnesses.get(read);
  if (!witness || witness.context !== ctx || witness.scope !== scopeFor(session)
    || witness.kind !== read.kind || witness.operationId !== read.operationId
    || witness.catalogProjection !== read.catalogProjection
    || witness.readHandle.operationId !== read.readHandle.operationId || witness.readHandle.kind !== read.readHandle.kind) {
    throw new Error('task_split_read_handle_not_from_scoped_inspection');
  }
  return witness;
}

function selectedObservedOffer(witness: SplitReadWitness, selection: SplitResourceSelection): SplitReadOffer {
  const key = `${requiredString(selection.resourceId, 'resource_id')}:${requiredString(selection.offerId, 'offer_id')}`;
  const offer = witness.offers.get(key);
  if (!offer) throw new Error('task_split_selection_not_advertised_by_read');
  return offer;
}

/** Validate the SDK v2 resource object and bind its URL to the selected local pay route. */
export function splitPaymentChallengeResourcePath(value: unknown, expectedPath: string): string {
  const declaration = record(value);
  const resource = record(declaration?.resource);
  if (declaration?.x402Version !== 2 || !resource || typeof resource.url !== 'string') {
    throw new Error('task_split_payment_challenge_invalid');
  }
  let resourceUrl: URL;
  try { resourceUrl = new URL(resource.url); }
  catch { throw new Error('task_split_payment_challenge_resource_invalid'); }
  if (!['http:', 'https:'].includes(resourceUrl.protocol) || resourceUrl.username || resourceUrl.password
    || resourceUrl.search || resourceUrl.hash || resourceUrl.origin !== 'http://localhost'
    || (resource.mimeType !== undefined && resource.mimeType !== 'application/json')) {
    throw new Error('task_split_payment_challenge_resource_invalid');
  }
  if (resourceUrl.pathname !== expectedPath) throw new Error('task_split_payment_challenge_route_mismatch');
  return resourceUrl.pathname;
}

function challengeRequirements(ctx: ProbeContext, session: GenerationSession, body: unknown, headers: { get(name: string): string | null }, accepted: SplitAcceptedTerms, operationId: string): { declaration: PaymentRequired; requirements: PaymentRequirements } {
  const declaration = session.signer.httpClient.getPaymentRequiredResponse((name) => headers.get(name), body);
  const expectedPath = `/tools/${session.envId}/pay`;
  splitPaymentChallengeResourcePath(declaration, expectedPath);

  if (!Array.isArray(declaration.accepts) || declaration.accepts.length !== 1) {
    throw new Error('task_split_payment_challenge_requirements_ambiguous');
  }
  const requirements = declaration.accepts[0]!;
  const extra = record(requirements.extra);
  if (requirements.scheme !== accepted.scheme || requirements.network !== accepted.network
    || requirements.asset.toLowerCase() !== accepted.asset.toLowerCase() || requirements.amount !== accepted.amount
    || requirements.payTo.toLowerCase() !== accepted.payTo.toLowerCase()
    || extra?.assetTransferMethod !== ctx.runtime.manifest.x402.assetTransferMethod
    || extra.paymentFlow !== 'authorization'
    || extra.name !== ctx.runtime.manifest.x402.eip712Domain.name
    || extra.version !== ctx.runtime.manifest.x402.eip712Domain.version) {
    throw new Error('task_split_payment_challenge_terms_mismatch');
  }
  if (headers.get('x-bef-operation-id')?.toLowerCase() !== operationId.toLowerCase()) {
    throw new Error('task_split_payment_challenge_operation_mismatch');
  }
  return { declaration, requirements };
}

function validatePaymentReceiptBody(value: unknown, operationId: string, txHash: string, terms: SplitAcceptedTerms): Record<string, unknown> {
  const body = record(value);
  const payment = record(body?.payment);
  const bodyKeys = body ? Object.keys(body).sort().join(',') : '';
  const paymentKeys = payment ? Object.keys(payment).sort().join(',') : '';
  if (!body || bodyKeys !== 'deliveryHandle,operationId,payment,status' || body.operationId !== operationId
    || body.deliveryHandle !== operationId || body.status !== 'payment_confirmed'
    || !payment || paymentKeys !== 'amount,asset,network,payTo,receiptStatus,transactionHash'
    || String(payment.transactionHash).toLowerCase() !== txHash.toLowerCase()
    || payment.receiptStatus !== 'success' || payment.amount !== terms.amount
    || String(payment.asset).toLowerCase() !== terms.asset.toLowerCase()
    || payment.network !== terms.network || String(payment.payTo).toLowerCase() !== terms.payTo.toLowerCase()) {
    throw new Error('task_split_payment_receipt_metadata_invalid');
  }
  return body;
}

function operationFor(facts: Awaited<ReturnType<typeof readCaseDatabaseFacts>>, operationId: string) {
  const rows = facts.operations.filter((row) => String(row.operation_id) === operationId);
  if (rows.length !== 1) throw new Error('task_split_database_operation_missing');
  return rows[0]!;
}

function assertSelectedOperation(manifest: RuntimeManifest, operation: Record<string, unknown>, operationId: string, offer: SplitReadOffer, expectedStatus: 'awaiting_payment' | 'settled' | 'delivered', txHash?: string): void {
  const { resource, offer: pin } = manifestOffer(manifest, offer.resourceId, offer.offerId);
  if (String(operation.operation_id) !== operationId || operation.operation_kind !== 'purchase'
    || operation.status !== expectedStatus || String(operation.selected_offer_id) !== offer.offerId
    || String(operation.selected_amount_units) !== pin.amount
    || String(operation.selected_resource_id) !== offer.resourceId
    || String(operation.selected_resource_sha256).toLowerCase() !== resource.resourceSha256.toLowerCase()
    || (txHash !== undefined && String(operation.transaction_hash).toLowerCase() !== txHash.toLowerCase())) {
    throw new Error('task_split_database_purchase_binding_mismatch');
  }
}

function x402ObservationMatches(snapshot: Awaited<ReturnType<ProbeContext['database']['snapshot']>>, operationId: string, txHash: string): boolean {
  return snapshot.x402Observations.some((row) => row.phase === 'settle' && row.outcome === 'success'
    && String(row.transaction_hash).toLowerCase() === txHash.toLowerCase()
    && String(row.operation_id) === operationId);
}

function facilitatorCost(facts: Awaited<ReturnType<typeof readCaseDatabaseFacts>>, operationId: string, txHash: string, facilitator: string): Record<string, unknown> {
  const costs = facts.transactionCosts.filter((row) => String(row.operation_id) === operationId);
  const cost = costs.length === 1 ? costs[0]! : null;
  if (!cost || cost.payer_role !== 'facilitator' || cost.receipt_status !== 'success'
    || String(cost.transaction_hash).toLowerCase() !== txHash.toLowerCase()
    || String(cost.payer_address).toLowerCase() !== facilitator
    || String(cost.transaction_from).toLowerCase() !== facilitator
    || String(cost.receipt_from).toLowerCase() !== facilitator
    || !/^[1-9][0-9]*$/.test(String(cost.gas_used ?? ''))
    || !/^(?:0|[1-9][0-9]*)$/.test(String(cost.effective_gas_price_wei ?? ''))
    || !/^[1-9][0-9]*$/.test(String(cost.gas_cost_wei ?? ''))
    || BigInt(String(cost.gas_used)) * BigInt(String(cost.effective_gas_price_wei)) !== BigInt(String(cost.gas_cost_wei))) {
    throw new Error('task_split_facilitator_gas_attribution_invalid');
  }
  return cost;
}

/**
 * Pay and retrieve only from the caller's previously observed scoped read.
 * This function deliberately has no catalog/offer GET path.
 * AICODE-NOTE: The WeakMap is only an accidental-binding guard; participant HTTP,
 * exact raw response bytes, and readonly PostgreSQL rows remain the durable proof.
 */
export async function payAndRetrieveSplitResource(
  ctx: ProbeContext,
  session: GenerationSession,
  selection: SplitResourceSelection,
  existingReadHandle: SplitReadHandle,
  options: SplitCaptureOptions,
): Promise<SplitPaymentCapture> {
  assertSession(ctx, session);
  const witness = assertReadWitness(ctx, session, existingReadHandle);
  const accepted = selectedObservedOffer(witness, selection);
  const { resource, offer: pinnedOffer } = manifestOffer(ctx.runtime.manifest, accepted.resourceId, accepted.offerId);
  const facilitator = facilitatorAddress(ctx);
  const expectedTerms = observedTerms(accepted.acceptedTerms, ctx.runtime.manifest, facilitator, pinnedOffer.amount);
  if (canonicalJson(expectedTerms) !== canonicalJson(accepted.acceptedTerms)) {
    throw new Error('task_split_accepted_terms_manifest_mismatch');
  }
  const pinnedResources = await loadPinnedResources(ctx.runtime.manifest);
  const pinnedResource = pinnedResources.get(resource.resourceId);
  if (!pinnedResource || pinnedResource.hash.toLowerCase() !== resource.resourceSha256.toLowerCase()
    || sha256Bytes(pinnedResource.bytes).toLowerCase() !== resource.resourceSha256.toLowerCase()) {
    throw new Error('task_split_pinned_resource_bytes_mismatch');
  }

  const label = safeLabel(options.label);
  const idempotencyKey = randomUUID();
  const payUrl = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/pay`);
  const payBody = {
    resourceId: accepted.resourceId,
    offerId: accepted.offerId,
    readHandle: witness.readHandle,
    acceptedTerms: expectedTerms,
  };
  const headers = participantHeaders(session, idempotencyKey);
  const challenge = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-pay-challenge`, method: 'POST',
    url: payUrl, headers, body: payBody, operationId: null, variantId: options.variantId,
    resolveOperationId: async (_status, body) => typeof record(body)?.operationId === 'string'
      ? String(record(body)!.operationId) : null,
  });
  if (challenge.status !== 402) throw new Error(`task_split_pay_challenge_failed_${challenge.status}`);
  const challengeOperationId = challenge.operationId ?? challenge.headers.get('x-bef-operation-id');
  if (!challengeOperationId || !UUID.test(challengeOperationId)) throw new Error('task_split_pay_challenge_operation_missing');
  const challengeBody = record(challenge.body);
  if (challengeBody?.operationId !== undefined && challengeBody.operationId !== challengeOperationId) {
    throw new Error('task_split_pay_challenge_operation_mismatch');
  }
  const challengeSnapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, idempotencyKey,
    variantId: options.variantId, label: `${label}-${challengeOperationId}-challenge-idempotency-proof`,
  });
  if (challengeSnapshot.operations.length !== 1
    || String(challengeSnapshot.operations[0]!.operation_id) !== challengeOperationId
    || String(challengeSnapshot.operations[0]!.participant_id) !== session.participantId
    || String(challengeSnapshot.operations[0]!.request_sha256).toLowerCase() !== jsonSha256({
      method: 'POST', path: `/tools/${session.envId}/pay`, body: payBody,
    })) {
    throw new Error('task_split_pay_challenge_idempotency_binding_mismatch');
  }
  const challengeFacts = await readCaseDatabaseFacts(ctx, session, `${label}-${challengeOperationId}-challenge`, options.variantId);
  const pending = operationFor(challengeFacts, challengeOperationId);
  assertSelectedOperation(ctx.runtime.manifest, pending, challengeOperationId, accepted, 'awaiting_payment');
  if (!['not_submitted', 'unknown'].includes(String(pending.receipt_status)) || pending.transaction_hash !== null
    || challengeFacts.payments.some((row) => String(row.operation_id) === challengeOperationId)
    || challengeFacts.deliveries.some((row) => String(row.operation_id) === challengeOperationId)) {
    throw new Error('task_split_challenge_database_effects_unexpected');
  }
  const { declaration, requirements } = challengeRequirements(ctx, session, challenge.body, challenge.headers, expectedTerms, challengeOperationId);

  // Exactly one signed retry is made, with the original body and idempotency key.
  // If this response is ambiguous, fail closed; never resubmit or replace the payment.
  const signed = await createSignedPayload(session.signer, declaration, requirements);
  const paid = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-pay-signed-retry`, method: 'POST',
    url: payUrl, headers: { ...headers, ...signed.headers }, body: payBody,
    operationId: challengeOperationId, variantId: options.variantId, includeRawResponseBytes: true,
  });
  if (paid.status !== 200 || paid.operationId !== challengeOperationId) {
    throw new Error(`task_split_paid_response_unconfirmed_${paid.status}`);
  }
  assertOperationResponseHeader(paid.headers, challengeOperationId);
  const settlement = readSettlementHeader(session.signer.httpClient, paid.headers);
  const transactionHash = settlement?.transaction;
  if (!settlement?.success || typeof transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(transactionHash)) {
    throw new Error('task_split_settlement_header_invalid');
  }
  const paymentReceipt = validatePaymentReceiptBody(paid.body, challengeOperationId, transactionHash, expectedTerms);
  const paidAction = await persistActualResponse(ctx, challengeOperationId, 'pay', paid.rawBody);

  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
    operationId: challengeOperationId, variantId: options.variantId, label: `${label}-${challengeOperationId}-settlement-receipt`,
  });
  const transfers = transferEvents(receipt, expectedTerms.asset).filter((event) =>
    event.from.toLowerCase() === session.payerAddress.toLowerCase()
    && event.to.toLowerCase() === facilitator
    && event.amount === BigInt(expectedTerms.amount));
  if (receipt.status.toLowerCase() !== '0x1' || receipt.transactionHash.toLowerCase() !== transactionHash.toLowerCase()
    || receipt.from.toLowerCase() !== facilitator || transfers.length !== 1) {
    throw new Error('task_split_settlement_receipt_or_transfer_mismatch');
  }
  const settlementBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: receipt.blockNumber,
    operationId: challengeOperationId, variantId: options.variantId,
    label: `${label}-${challengeOperationId}-settlement-receipt-block`,
  });
  if (BigInt(settlementBlock.number) !== BigInt(receipt.blockNumber)
    || settlementBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) {
    throw new Error('task_split_settlement_receipt_block_mismatch');
  }

  const paidFacts = await readCaseDatabaseFacts(ctx, session, `${label}-${challengeOperationId}-paid`, options.variantId);
  const paidOperation = operationFor(paidFacts, challengeOperationId);
  assertSelectedOperation(ctx.runtime.manifest, paidOperation, challengeOperationId, accepted, 'settled', transactionHash);
  if (String(paidOperation.response_sha256).toLowerCase() !== jsonSha256(paid.body)) {
    throw new Error('task_split_paid_response_database_hash_mismatch');
  }
  const paymentRows = paidFacts.payments.filter((row) => String(row.operation_id) === challengeOperationId);
  if (paymentRows.length !== 1 || paidFacts.deliveries.some((row) => String(row.operation_id) === challengeOperationId)) {
    throw new Error('task_split_paid_database_effects_mismatch');
  }
  const payment = paymentRows[0]!;
  if (payment.receipt_status !== 'success' || String(payment.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || String(payment.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || String(payment.facilitator_address).toLowerCase() !== facilitator
    || String(payment.network) !== expectedTerms.network
    || String(payment.asset_address).toLowerCase() !== expectedTerms.asset.toLowerCase()
    || String(payment.amount_units) !== expectedTerms.amount || String(payment.token_delta_units) !== expectedTerms.amount) {
    throw new Error('task_split_payment_database_binding_mismatch');
  }
  const paySnapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId: challengeOperationId,
    variantId: options.variantId, label: `${label}-${challengeOperationId}-settlement-proof`,
  });
  if (paySnapshot.operations.length !== 1 || paySnapshot.operations[0]!.status !== 'settled'
    || paySnapshot.operations[0]!.receipt_status !== 'success'
    || String(paySnapshot.operations[0]!.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || paySnapshot.payments.length !== 1 || paySnapshot.deliveries.length !== 0
    || !x402ObservationMatches(paySnapshot, challengeOperationId, transactionHash)) {
    throw new Error('task_split_pay_durable_settlement_proof_mismatch');
  }
  const facilitatorGas = facilitatorCost(paidFacts, challengeOperationId, transactionHash, facilitator);
  if (paidFacts.transactionCosts.some((row) => String(row.operation_id) === challengeOperationId && row.payer_role === 'participant')) {
    throw new Error('task_split_participant_gas_cost_present');
  }

  // The delivery GET has scoped bearer/generation/idempotency auth; it does not include a payment signature.
  const retrieveUrl = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/retrieve?operationId=${encodeURIComponent(challengeOperationId)}`);
  const retrieved = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-retrieve`, method: 'GET', url: retrieveUrl,
    headers: buildSplitRetrieveHeaders(session), operationId: challengeOperationId,
    variantId: options.variantId, includeRawResponseBytes: true,
  });
  if (retrieved.status !== 200 || retrieved.operationId !== challengeOperationId) {
    throw new Error(`task_split_retrieve_failed_${retrieved.status}`);
  }
  assertOperationResponseHeader(retrieved.headers, challengeOperationId);
  const envelope = record(retrieved.body);
  if (!envelope || envelope.operationId !== challengeOperationId) throw new Error('task_split_retrieve_operation_mismatch');
  const deliveryProjection = projectDeliveryEnvelope({
    envelope, expectedResourceId: resource.resourceId,
    expectedContentHash: resource.resourceSha256, provenanceId: resource.provenance.classification,
  });
  if (canonicalJson(deliveryProjection.parsedContent) !== canonicalJson(pinnedResource.parsed)) {
    throw new Error('task_split_retrieved_content_differs_from_pinned_resource');
  }
  const deliveryContentPath = `task-split-resource/content/${challengeOperationId}-${resource.resourceSha256.toLowerCase()}.json`;
  const contentBytes = Buffer.from(deliveryProjection.projection.contentBytes, 'base64');
  await ctx.evidence.writeRawJson(deliveryContentPath, contentBytes, 'actual-tool-http-delivered-content');
  const retrievedAction = await persistActualResponse(ctx, challengeOperationId, 'retrieve', retrieved.rawBody);

  const deliveredFacts = await readCaseDatabaseFacts(ctx, session, `${label}-${challengeOperationId}-delivered`, options.variantId);
  const deliveredOperation = operationFor(deliveredFacts, challengeOperationId);
  assertSelectedOperation(ctx.runtime.manifest, deliveredOperation, challengeOperationId, accepted, 'delivered', transactionHash);
  if (!deferredPaymentReceiptHashMatches(deliveredOperation.response_sha256, paid.body)) {
    throw new Error('task_split_delivery_response_database_hash_mismatch');
  }
  const deliveredPayments = deliveredFacts.payments.filter((row) => String(row.operation_id) === challengeOperationId);
  const deliveries = deliveredFacts.deliveries.filter((row) => String(row.operation_id) === challengeOperationId);
  if (deliveredOperation.receipt_status !== 'success' || deliveredPayments.length !== 1 || deliveries.length !== 1
    || deliveries[0]!.resource_id !== resource.resourceId
    || String(deliveries[0]!.content_sha256).toLowerCase() !== resource.resourceSha256.toLowerCase()
    || Number(deliveries[0]!.content_bytes) !== contentBytes.byteLength) {
    throw new Error('task_split_delivery_database_binding_mismatch');
  }
  const finalSnapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId: challengeOperationId,
    variantId: options.variantId, label: `${label}-${challengeOperationId}-delivery-proof`,
  });
  if (finalSnapshot.operations.length !== 1 || finalSnapshot.operations[0]!.status !== 'delivered'
    || finalSnapshot.operations[0]!.receipt_status !== 'success'
    || String(finalSnapshot.operations[0]!.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || finalSnapshot.payments.length !== 1 || finalSnapshot.deliveries.length !== 1
    || String(finalSnapshot.deliveries[0]!.content_sha256).toLowerCase() !== resource.resourceSha256.toLowerCase()) {
    throw new Error('task_split_delivery_readonly_snapshot_mismatch');
  }
  facilitatorCost(deliveredFacts, challengeOperationId, transactionHash, facilitator);
  if (deliveredFacts.transactionCosts.some((row) => String(row.operation_id) === challengeOperationId && row.payer_role === 'participant')) {
    throw new Error('task_split_participant_gas_cost_present');
  }

  return {
    operationId: challengeOperationId,
    transactionHash: transactionHash.toLowerCase(),
    paymentReceipt,
    settlementReceipt: {
      blockNumber: BigInt(receipt.blockNumber).toString(),
      blockHash: receipt.blockHash.toLowerCase(),
      status: receipt.status.toLowerCase(),
      transactionHash: receipt.transactionHash.toLowerCase(),
    },
    envelope,
    deliveryProjection,
    facilitatorGas,
    deliveryContentPath,
    deliveryContentSha256: sha256Bytes(contentBytes),
    participantActions: [paidAction, retrievedAction],
  };
}
