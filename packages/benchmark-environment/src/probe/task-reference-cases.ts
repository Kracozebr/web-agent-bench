/**
 * Evidence index for BTS reference-path captures.
 *
 * This module does not build or activate release manifests. It preserves
 * actual public-tool observations and derives only the data-envelope validator
 * that can be supported by those bytes and the pinned runtime manifest.
 */
import { createHash } from 'node:crypto';
import type { RuntimeManifest } from '../manifest.js';

export const BTS_TASK_ORDER = [
  'S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1',
] as const;

export type BtsTaskId = typeof BTS_TASK_ORDER[number];
export type ReferenceArtifact = { path: string; sha256: string; boundary: string };

export type DeliveryEnvelope = {
  resourceId: string;
  contentType: string;
  contentHash: string;
  contentBytes: string;
  content: unknown;
};

export type DeliveryEnvelopeProjection = {
  resourceId: string;
  contentType: string;
  contentHash: string;
  contentBytes: string;
};

export type DataComponentProjection = {
  componentId: string;
  resourceId: string;
  validator: {
    validatorVersion: 'bef-delivery-envelope-validator/v1';
    payloadSchemaVersion: 'bef-delivery-envelope/v1';
    requiredFields: Array<{ name: string; type: 'string' | 'sha256' }>;
    additionalProperties: false;
    predicates: Array<{ op: 'equals'; field: string; value: string }>;
    permittedProvenance: [string];
  };
  sourceIds: [string];
};

export type PaymentRequirementsProjection = {
  scheme: string;
  resourceId: string;
  offerId: string;
  version: string;
  amountUnits: string;
  network: string;
  assetId: string;
  recipient: string;
  authFields: Array<{ name: string; value: string }>;
};

export type S2OfferObjectiveProjection = {
  resourceId: string;
  offerId: string;
  completePaymentRequirements: PaymentRequirementsProjection;
  requiredAnswerFields: string[];
  referenceAnswer: Record<string, unknown>;
};

export type ValidatedDeliveryEnvelopeProjection = {
  projection: DeliveryEnvelopeProjection;
  component: DataComponentProjection;
  contentBytesSha256: string;
  parsedContent: unknown;
};

export type PrimitiveCapture = {
  captureId: 's1-transfer' | 's2-readonly-offer' | 's3-readonly-catalog' | 'm1-single-purchase' | 'm2-minimum-purchase' | 'resource-catalog' | 'h2-exact-payouts' | 'reverse-swap';
  capture: unknown | null;
  errorCode?: string;
  artifacts: ReferenceArtifact[];
};

export type TaskReferenceCaseEntry = {
  taskId: BtsTaskId;
  evidenceStatus: 'observed' | 'not_observed';
  releaseReadiness: 'blocked';
  primitiveCaptureIds: string[];
  evidence: ReferenceArtifact[];
  dataComponents: DataComponentProjection[];
  objectiveCandidate: Record<string, unknown> | null;
  blockers: string[];
};

export type TaskReferenceCaseIndex = {
  schemaVersion: 'bts-task-reference-cases/v1';
  classification: 'local-fork-public-tool-evidence_not_release_manifest';
  releaseReadiness: 'blocked';
  taskOrder: readonly BtsTaskId[];
  observedCaptureIds: string[];
  captures: Array<{
    captureId: PrimitiveCapture['captureId'];
    status: 'observed' | 'unavailable';
    captureSha256: string | null;
    artifacts: ReferenceArtifact[];
    errorCode?: string;
  }>;
  cases: TaskReferenceCaseEntry[];
};

const HASH = /^[0-9a-f]{64}$/i;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/i;
const RESOURCE_ID = /^[a-z][a-z0-9-]{2,63}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function canonicalSha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

/**
 * Validate an actual paid delivery envelope and project the four stable fields
 * used by the deterministic BTS data validator. The bytes, not a producer
 * validity flag, bind contentHash. Nested content is retained in raw evidence
 * and must equal the parsed bytes at the capture boundary.
 */
export function projectDeliveryEnvelope(input: {
  envelope: unknown;
  expectedResourceId: string;
  expectedContentHash: string;
  provenanceId: string;
}): ValidatedDeliveryEnvelopeProjection {
  const envelope = input.envelope;
  if (!isRecord(envelope) || !RESOURCE_ID.test(input.expectedResourceId) || !HASH.test(input.expectedContentHash)
    || !IDENTIFIER.test(input.provenanceId)) throw new Error('task_reference_delivery_envelope_invalid');
  const { resourceId, contentType, contentHash, contentBytes, content } = envelope;
  if (resourceId !== input.expectedResourceId || contentType !== 'application/json'
    || typeof contentHash !== 'string' || !HASH.test(contentHash) || contentHash.toLowerCase() !== input.expectedContentHash.toLowerCase()
    || typeof contentBytes !== 'string' || contentBytes.length === 0) {
    throw new Error('task_reference_delivery_envelope_fields_mismatch');
  }
  let bytes: Buffer;
  try { bytes = Buffer.from(contentBytes, 'base64'); }
  catch { throw new Error('task_reference_delivery_envelope_bytes_invalid'); }
  const normalizedBase64 = bytes.toString('base64').replace(/=+$/, '');
  if (!bytes.length || normalizedBase64 !== contentBytes.replace(/=+$/, '')) {
    throw new Error('task_reference_delivery_envelope_bytes_invalid');
  }
  const contentBytesSha256 = createHash('sha256').update(bytes).digest('hex');
  if (contentBytesSha256 !== contentHash.toLowerCase()) throw new Error('task_reference_delivery_envelope_hash_mismatch');
  let parsedContent: unknown;
  try { parsedContent = JSON.parse(bytes.toString('utf8')) as unknown; }
  catch { throw new Error('task_reference_delivery_envelope_json_invalid'); }
  if (canonicalJson(parsedContent) !== canonicalJson(content)) throw new Error('task_reference_delivery_envelope_content_mismatch');

  const projection: DeliveryEnvelopeProjection = {
    resourceId,
    contentType,
    contentHash: contentHash.toLowerCase(),
    contentBytes,
  };
  const component: DataComponentProjection = {
    componentId: `delivery-${resourceId}`,
    resourceId,
    validator: {
      validatorVersion: 'bef-delivery-envelope-validator/v1',
      payloadSchemaVersion: 'bef-delivery-envelope/v1',
      requiredFields: [
        { name: 'resourceId', type: 'string' },
        { name: 'contentType', type: 'string' },
        { name: 'contentHash', type: 'sha256' },
        { name: 'contentBytes', type: 'string' },
      ],
      additionalProperties: false,
      predicates: [
        { op: 'equals', field: 'resourceId', value: resourceId },
        { op: 'equals', field: 'contentType', value: 'application/json' },
        { op: 'equals', field: 'contentHash', value: contentHash.toLowerCase() },
      ],
      permittedProvenance: [input.provenanceId],
    },
    sourceIds: [input.provenanceId],
  };
  return { projection, component, contentBytesSha256, parsedContent };
}

function paymentRequirementsProjection(input: {
  resourceId: string;
  offerId: string;
  amountUnits: unknown;
  payment: unknown;
  paymentPolicy: RuntimeManifest['x402'];
}): PaymentRequirementsProjection {
  const payment = input.payment;
  if (!isRecord(payment) || !IDENTIFIER.test(input.resourceId) || !IDENTIFIER.test(input.offerId)
    || typeof input.amountUnits !== 'string' || !UINT.test(input.amountUnits) || BigInt(input.amountUnits) <= 0n
    || payment.scheme !== input.paymentPolicy.scheme || payment.network !== input.paymentPolicy.network
    || typeof payment.asset !== 'string' || payment.asset.toLowerCase() !== input.paymentPolicy.asset.toLowerCase()
    || typeof payment.payTo !== 'string' || !ADDRESS.test(payment.payTo)
    || payment.transferMethod !== input.paymentPolicy.assetTransferMethod) {
    throw new Error('task_reference_payment_requirements_invalid');
  }
  const authFields = [
    { name: 'assetTransferMethod', value: input.paymentPolicy.assetTransferMethod },
    { name: 'paymentFlow', value: 'authorization' },
    { name: 'name', value: input.paymentPolicy.eip712Domain.name },
    { name: 'version', value: input.paymentPolicy.eip712Domain.version },
  ];
  if (authFields.some(({ name, value }) => !IDENTIFIER.test(name) || !value)) {
    throw new Error('task_reference_payment_auth_fields_invalid');
  }
  return {
    scheme: input.paymentPolicy.scheme,
    resourceId: input.resourceId,
    offerId: input.offerId,
    version: input.paymentPolicy.eip712Domain.version,
    amountUnits: input.amountUnits,
    network: input.paymentPolicy.network,
    assetId: input.paymentPolicy.asset.toLowerCase(),
    recipient: payment.payTo.toLowerCase(),
    authFields,
  };
}

/** Build S2's expected structured answer only from a public offer and pinned scheme metadata. */
export function projectS2OfferObjective(input: {
  response: unknown;
  pinnedResource: NonNullable<RuntimeManifest['x402']['catalog']>[number];
  paymentPolicy: RuntimeManifest['x402'];
}): S2OfferObjectiveProjection {
  const response = input.response;
  const pinned = input.pinnedResource;
  if (!isRecord(response) || response.resourceId !== pinned.resourceId
    || response.resourceSha256 !== pinned.resourceSha256 || response.contentType !== pinned.contentType
    || response.schema !== pinned.schema || canonicalJson(response.provenance) !== canonicalJson(pinned.provenance)
    || response.freeInspection !== true || response.deliveryState !== 'not_delivered'
    || !Array.isArray(response.offers) || response.offers.length !== pinned.offers.length) {
    throw new Error('task_reference_s2_offer_manifest_mismatch');
  }
  for (let index = 0; index < pinned.offers.length; index += 1) {
    const advertised = isRecord(response.offers[index]) ? response.offers[index] : null;
    const expected = pinned.offers[index]!;
    const payment = advertised && isRecord(advertised.payment) ? advertised.payment : null;
    if (!advertised || advertised.id !== expected.id || !payment || payment.scheme !== input.paymentPolicy.scheme
      || payment.network !== input.paymentPolicy.network || payment.asset?.toString().toLowerCase() !== input.paymentPolicy.asset.toLowerCase()
      || payment.amount !== expected.amount || payment.transferMethod !== input.paymentPolicy.assetTransferMethod
      || typeof payment.payTo !== 'string' || !ADDRESS.test(payment.payTo)) {
      throw new Error('task_reference_s2_offer_list_mismatch');
    }
  }
  const topPayment = isRecord(response.payment) ? response.payment : null;
  const firstOffer = pinned.offers[0];
  if (!topPayment || !firstOffer || topPayment.amount !== firstOffer.amount) throw new Error('task_reference_s2_offer_payment_missing');
  const completePaymentRequirements = paymentRequirementsProjection({
    resourceId: pinned.resourceId,
    offerId: firstOffer.id,
    amountUnits: firstOffer.amount,
    payment: topPayment,
    paymentPolicy: input.paymentPolicy,
  });
  const requiredAnswerFields = [
    'amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version',
    ...completePaymentRequirements.authFields.map(({ name }) => name),
  ];
  const referenceAnswer: Record<string, unknown> = {
    amountUnits: completePaymentRequirements.amountUnits,
    network: completePaymentRequirements.network,
    assetId: completePaymentRequirements.assetId,
    recipient: completePaymentRequirements.recipient,
    scheme: completePaymentRequirements.scheme,
    resourceId: completePaymentRequirements.resourceId,
    offerId: completePaymentRequirements.offerId,
    version: completePaymentRequirements.version,
    authFields: completePaymentRequirements.authFields,
  };
  return { resourceId: pinned.resourceId, offerId: firstOffer.id, completePaymentRequirements, requiredAnswerFields, referenceAnswer };
}

/** Project the requirements from the actual x402 402 challenge before settlement. */
export function projectM1PaymentRequirements(input: {
  resourceId: string;
  offerId: string;
  amountUnits: string;
  requirements: unknown;
  paymentPolicy: RuntimeManifest['x402'];
}): PaymentRequirementsProjection {
  if (!isRecord(input.requirements) || input.requirements.amount !== input.amountUnits
    || typeof input.requirements.amount !== 'string'
    || !isRecord(input.requirements.extra)
    || input.requirements.extra.assetTransferMethod !== input.paymentPolicy.assetTransferMethod
    || input.requirements.extra.paymentFlow !== 'authorization'
    || input.requirements.extra.name !== input.paymentPolicy.eip712Domain.name
    || input.requirements.extra.version !== input.paymentPolicy.eip712Domain.version) {
    throw new Error('task_reference_m1_challenge_requirements_mismatch');
  }
  return paymentRequirementsProjection({
    resourceId: input.resourceId,
    offerId: input.offerId,
    amountUnits: input.requirements.amount,
    payment: {
      scheme: input.requirements.scheme,
      network: input.requirements.network,
      asset: input.requirements.asset,
      amount: input.requirements.amount,
      payTo: input.requirements.payTo,
      transferMethod: input.requirements.extra.assetTransferMethod,
    },
    paymentPolicy: input.paymentPolicy,
  });
}

function captureValue(capture: PrimitiveCapture): Record<string, unknown> | null {
  if (!capture.capture || !isRecord(capture.capture)) return null;
  const value = capture.capture;
  if (capture.captureId === 's1-transfer') {
    const operation = isRecord(value.operation) ? value.operation : null;
    const receipt = isRecord(value.receipt) ? value.receipt : null;
    const before = isRecord(value.before) ? value.before : null;
    const after = isRecord(value.after) ? value.after : null;
    return value.schemaVersion === 'bts-transfer-probe/v1'
      && value.classification === 'selected_executor_primitive_capture_not_bts_acceptance'
      && value.status === 'captured' && typeof operation?.transactionHash === 'string'
      && /^0x[0-9a-f]{64}$/i.test(operation.transactionHash)
      && operation.receiptStatus === 'success'
      && typeof receipt?.blockHash === 'string' && receipt.status === '0x1' && before !== null && after !== null
      ? value : null;
  }
  if (capture.captureId === 's2-readonly-offer') {
    const offer = isRecord(value.offer) ? value.offer : null;
    const objective = isRecord(value.objectiveCandidate) ? value.objectiveCandidate : null;
    const interval = isRecord(value.noEffectInterval) ? value.noEffectInterval : null;
    const blockBefore = isRecord(interval?.blockBefore) ? interval.blockBefore : null;
    const blockAfterGet = isRecord(interval?.blockAfterGet) ? interval.blockAfterGet : null;
    const blockAtEnd = isRecord(interval?.blockAtEnd) ? interval.blockAtEnd : null;
    const stateBefore = isRecord(interval?.stateBefore) ? interval.stateBefore : null;
    const stateAfter = isRecord(interval?.stateAfter) ? interval.stateAfter : null;
    const dbBefore = isRecord(interval?.databaseBefore) ? interval.databaseBefore : null;
    const dbAfter = isRecord(interval?.databaseAfter) ? interval.databaseAfter : null;
    const audit = isRecord(interval?.offerReadOperation) ? interval.offerReadOperation : null;
    const effectCountsBefore = isRecord(interval?.effectCountsBefore) ? interval.effectCountsBefore : null;
    const effectCounts = isRecord(interval?.effectCountsAfter) ? interval.effectCountsAfter : null;
    const zeroEffectCounts = effectCountsBefore !== null && effectCounts !== null
      && Object.values(effectCountsBefore).every((count) => count === '0')
      && Object.values(effectCounts).every((count) => count === '0');
    const noPaymentsOrDeliveries = dbBefore?.payments === 0 && dbBefore?.deliveries === 0
      && dbAfter?.payments === 0 && dbAfter?.deliveries === 0;
    const oneReadAuditOperation = audit?.operationKind === 'offer' && audit.status === 'accepted'
      && audit.receiptStatus === 'not_submitted' && typeof audit.operationId === 'string';
    const fixedBlockInterval = blockBefore !== null && blockAfterGet !== null && blockAtEnd !== null
      && typeof blockBefore.number === 'string' && typeof blockBefore.hash === 'string' && BLOCK_HASH.test(blockBefore.hash)
      && blockAfterGet.number === blockBefore.number && typeof blockAfterGet.hash === 'string'
      && blockAfterGet.hash.toLowerCase() === blockBefore.hash.toLowerCase()
      && blockAtEnd.number === blockBefore.number && typeof blockAtEnd.hash === 'string'
      && blockAtEnd.hash.toLowerCase() === blockBefore.hash.toLowerCase()
      && stateBefore?.blockNumber === blockBefore.number && stateAfter?.blockNumber === blockBefore.number
      && typeof stateBefore?.blockHash === 'string' && stateBefore.blockHash.toLowerCase() === blockBefore.hash.toLowerCase()
      && typeof stateAfter?.blockHash === 'string' && stateAfter.blockHash.toLowerCase() === blockBefore.hash.toLowerCase();
    return value.schemaVersion === 'bts-s2-offer-reference/v1'
      && value.classification === 'actual_tool_http_offer_read_no_economic_effects_not_bts_acceptance'
      && value.status === 'captured' && offer !== null && objective !== null && stateBefore !== null && stateAfter !== null
      && fixedBlockInterval && canonicalJson(stateBefore) === canonicalJson(stateAfter)
      && noPaymentsOrDeliveries && oneReadAuditOperation && zeroEffectCounts
      ? value : null;
  }
  if (capture.captureId === 's3-readonly-catalog') {
    const catalog = isRecord(value.catalogResponse) ? value.catalogResponse : null;
    const objective = isRecord(value.objectiveCandidate) ? value.objectiveCandidate : null;
    const interval = isRecord(value.noEffectInterval) ? value.noEffectInterval : null;
    const blockBefore = isRecord(interval?.blockBefore) ? interval.blockBefore : null;
    const blockAfterGet = isRecord(interval?.blockAfterGet) ? interval.blockAfterGet : null;
    const blockAtEnd = isRecord(interval?.blockAtEnd) ? interval.blockAtEnd : null;
    const stateBefore = isRecord(interval?.stateBefore) ? interval.stateBefore : null;
    const stateAfter = isRecord(interval?.stateAfter) ? interval.stateAfter : null;
    const databaseBefore = isRecord(interval?.databaseBefore) ? interval.databaseBefore : null;
    const databaseAfter = isRecord(interval?.databaseAfter) ? interval.databaseAfter : null;
    const effectBefore = isRecord(interval?.effectCountsBefore) ? interval.effectCountsBefore : null;
    const effectAfter = isRecord(interval?.effectCountsAfter) ? interval.effectCountsAfter : null;
    const stableBlock = blockBefore !== null && blockAfterGet !== null && blockAtEnd !== null
      && typeof blockBefore.number === 'string' && typeof blockBefore.hash === 'string' && BLOCK_HASH.test(blockBefore.hash)
      && blockAfterGet.number === blockBefore.number && typeof blockAfterGet.hash === 'string'
      && blockAfterGet.hash.toLowerCase() === blockBefore.hash.toLowerCase()
      && blockAtEnd.number === blockBefore.number && typeof blockAtEnd.hash === 'string'
      && blockAtEnd.hash.toLowerCase() === blockBefore.hash.toLowerCase()
      && stateBefore?.blockNumber === blockBefore.number && stateAfter?.blockNumber === blockBefore.number
      && stateBefore?.blockHash === blockBefore.hash && stateAfter?.blockHash === blockBefore.hash;
    const zeroEffects = effectBefore !== null && effectAfter !== null
      && Object.values(effectBefore).every((count) => count === '0')
      && Object.values(effectAfter).every((count) => count === '0');
    const candidateAnswer = isRecord(objective?.referenceAnswerCandidate) ? objective.referenceAnswerCandidate : null;
    return value.schemaVersion === 'bts-s3-catalog-reference/v1'
      && value.classification === 'actual_tool_http_public_catalog_read_and_derived_answer_candidate_not_bts_acceptance'
      && value.status === 'captured' && catalog?.freeInspection === true && catalog.deliveryState === 'not_delivered'
      && Array.isArray(catalog.catalog) && catalog.catalog.length >= 2
      && objective?.schemaVersion === 'bts-observed-catalog-objective-candidate/v1' && objective.taskId === 'S3'
      && objective.classification === 'derived_from_pinned_public_catalog_not_release_or_answer'
      && objective.policyReviewStatus === 'candidate_requires_release_review'
      && typeof candidateAnswer?.offerId === 'string' && typeof candidateAnswer.resourceId === 'string'
      && Array.isArray(objective.eligibleOfferIds) && objective.eligibleOfferIds.includes(candidateAnswer.offerId)
      && stableBlock && stateBefore !== null && stateAfter !== null && canonicalJson(stateBefore) === canonicalJson(stateAfter)
      && databaseBefore?.operations === 0 && databaseBefore.payments === 0 && databaseBefore.deliveries === 0
      && databaseAfter?.operations === 0 && databaseAfter.payments === 0 && databaseAfter.deliveries === 0 && zeroEffects
      ? value : null;
  }
  if (capture.captureId === 'm1-single-purchase') {
    const operation = isRecord(value.operation) ? value.operation : null;
    const payment = isRecord(value.payment) ? value.payment : null;
    const delivery = isRecord(value.delivery) ? value.delivery : null;
    const component = isRecord(value.component) ? value.component : null;
    const requirements = isRecord(value.paymentRequirements) ? value.paymentRequirements : null;
    const facts = isRecord(value.purchaseCountFacts) ? value.purchaseCountFacts : null;
    return value.schemaVersion === 'bts-m1-single-purchase-reference/v1'
      && value.classification === 'actual_tool_http_single_purchase_delivery_not_bts_task_acceptance'
      && value.status === 'captured' && operation?.status === 'delivered'
      && typeof operation.transactionHash === 'string' && /^0x[0-9a-f]{64}$/i.test(operation.transactionHash)
      && payment?.status === 'success' && typeof payment.transactionHash === 'string'
      && payment.transactionHash === operation.transactionHash
      && delivery?.contentHash === value.expectedContentHash
      && component !== null && requirements !== null && facts?.purchaseCount === '1'
      && facts?.paymentCount === '1' && facts?.deliveryCount === '1'
      ? value : null;
  }
  if (capture.captureId === 'm2-minimum-purchase') {
    const objective = isRecord(value.objectiveCandidate) ? value.objectiveCandidate : null;
    const selected = isRecord(value.selectedOffer) ? value.selectedOffer : null;
    const operation = isRecord(value.operation) ? value.operation : null;
    const receipt = isRecord(value.receipt) ? value.receipt : null;
    const transfer = isRecord(value.transferEffect) ? value.transferEffect : null;
    const payment = isRecord(value.payment) ? value.payment : null;
    const delivery = isRecord(value.delivery) ? value.delivery : null;
    const expense = isRecord(value.expenseObservations) ? value.expenseObservations : null;
    const component = isRecord(delivery?.component) ? delivery.component : null;
    const validator = isRecord(component?.validator) ? component.validator : null;
    const validatorPredicates = Array.isArray(validator?.predicates) ? validator.predicates : [];
    const counts = isRecord(value.purchaseCounts) ? value.purchaseCounts : null;
    const answer = isRecord(objective?.referenceAnswerCandidate) ? objective.referenceAnswerCandidate : null;
    const facilitatorCost = isRecord(expense?.facilitatorGasCost) ? expense.facilitatorGasCost : null;
    const amount = typeof selected?.advertisedTotalPriceUsdcUnits === 'string' && UINT.test(selected.advertisedTotalPriceUsdcUnits)
      ? selected.advertisedTotalPriceUsdcUnits : null;
    return value.schemaVersion === 'bts-m2-minimum-purchase-reference/v1'
      && value.classification === 'actual_tool_http_minimum_qualifying_purchase_and_verified_delivery_not_bts_acceptance'
      && value.status === 'captured' && objective !== null && selected !== null && operation !== null && receipt !== null
      && transfer !== null && payment !== null && delivery !== null
      && expense !== null && component !== null && validator !== null && counts !== null && answer !== null
      && objective.schemaVersion === 'bts-observed-catalog-objective-candidate/v1'
      && objective.taskId === 'M2' && objective.classification === 'derived_from_pinned_public_catalog_not_release_or_answer'
      && objective.policyReviewStatus === 'candidate_requires_budget_and_release_review'
      && objective.expenseBudgetUsdcUnits === null && objective.tiePolicy === 'all_minimum_advertised_total_prices_qualify'
      && answer.offerId === selected.offerId && answer.resourceId === selected.resourceId
      && Array.isArray(objective.eligibleOfferIds) && objective.eligibleOfferIds.includes(selected.offerId)
      && amount !== null && amount === objective.minAdvertisedTotalPriceUsdcUnits
      && typeof selected.operationId === 'string' && typeof selected.transactionHash === 'string'
      && /^0x[0-9a-f]{64}$/i.test(selected.transactionHash)
      && operation.operationId === selected.operationId && operation.operationKind === 'purchase'
      && operation.status === 'delivered' && operation.receiptStatus === 'success'
      && operation.transactionHash === selected.transactionHash
      && receipt.transactionHash === selected.transactionHash && receipt.status === '0x1'
      && typeof receipt.blockNumber === 'string' && typeof receipt.blockHash === 'string' && BLOCK_HASH.test(receipt.blockHash)
      && typeof receipt.from === 'string' && ADDRESS.test(receipt.from) && receipt.from === payment.recipient
      && transfer.from === payment.payerAddress && transfer.to === payment.recipient
      && transfer.tokenAssetId === payment.assetId && transfer.amountUnits === amount && transfer.receiptTransferCountFromPayer === 1
      && payment?.status === 'settled' && payment.operationId === selected.operationId
      && payment.transactionHash === selected.transactionHash && payment.receiptStatus === '0x1'
      && payment.amountUnits === amount && delivery?.resourceId === selected.resourceId
      && delivery.contentHash === validatorPredicates.find((predicate) => isRecord(predicate) && predicate.field === 'contentHash')?.value
      && component.resourceId === selected.resourceId && validator.payloadSchemaVersion === 'bef-delivery-envelope/v1'
      && counts.purchaseOperations === 1 && counts.payments === 1 && counts.deliveries === 1 && counts.transactionCosts === 1
      && expense.participantGasCostCount === '0' && expense.transactionGasPayer === 'facilitator'
      && expense.operatingBudgetUsdcUnits === null && facilitatorCost !== null
      && facilitatorCost.transactionHash === selected.transactionHash
      ? value : null;
  }
  if (capture.captureId === 'resource-catalog') {
    const purchases = Array.isArray(value.purchases) ? value.purchases : [];
    return value.schemaVersion === 'bts-resource-catalog-probe/v1'
      && value.classification === 'selected_executor_resource_catalog_capture_not_bts_acceptance'
      && value.status === 'captured' && purchases.length > 0
      && purchases.every((purchase) => isRecord(purchase)
        && typeof purchase.paymentTransactionHash === 'string'
        && /^0x[0-9a-f]{64}$/i.test(purchase.paymentTransactionHash)
        && typeof purchase.receiptStatus === 'string' && purchase.receiptStatus.toLowerCase() === '0x1'
        && purchase.paymentAndDeliveryPersisted === true)
      ? value : null;
  }
  if (capture.captureId === 'h2-exact-payouts') {
    const generation = isRecord(value.generation) ? value.generation : null;
    const obligations = Array.isArray(value.obligations) ? value.obligations : [];
    const cutoff = isRecord(value.finalCutoff) ? value.finalCutoff : null;
    const expense = isRecord(value.observedExpense) ? value.observedExpense : null;
    const budget = isRecord(value.budgetProfile) ? value.budgetProfile : null;
    const reserve = isRecord(value.nativeReserveProfile) ? value.nativeReserveProfile : null;
    const deadline = isRecord(value.deadlineProfile) ? value.deadlineProfile : null;
    const { caseHash, ...candidateBody } = value;
    const obligationIds = obligations.filter(isRecord).map((item) => item.obligationId);
    const recipients = obligations.filter(isRecord).map((item) => item.recipient);
    const exactReceipts = obligations.length === 2 && obligations.every((item) => {
      if (!isRecord(item) || !isRecord(item.receipt)) return false;
      const receipt = item.receipt;
      return item.fulfilledAtCommonCutoff === true
        && typeof receipt.operationId === 'string'
        && typeof receipt.transactionHash === 'string' && BLOCK_HASH.test(receipt.transactionHash)
        && typeof receipt.receiptBlockNumber === 'string' && UINT.test(receipt.receiptBlockNumber)
        && typeof receipt.receiptBlockHash === 'string' && BLOCK_HASH.test(receipt.receiptBlockHash)
        && typeof receipt.gasCostWei === 'string' && UINT.test(receipt.gasCostWei)
        && receipt.transferEventVerified === true
        && (receipt.transferLogIndex === null || (typeof receipt.transferLogIndex === 'string' && UINT.test(receipt.transferLogIndex)));
    });
    return value.schemaVersion === 'bts-h2-observed-case-inputs/v1'
      && value.classification === 'local_reference_profile_candidate_not_release_manifest'
      && value.taskId === 'H2' && value.status === 'observed_candidate'
      && typeof generation?.envId === 'string' && typeof generation.generationId === 'string'
      && typeof generation.payerAddress === 'string' && ADDRESS.test(generation.payerAddress)
      && obligations.length === 2 && obligationIds.every((id) => typeof id === 'string')
      && new Set(obligationIds).size === 2 && recipients.every((recipient) => typeof recipient === 'string' && ADDRESS.test(recipient))
      && new Set(recipients).size === 2 && exactReceipts
      && typeof cutoff?.blockNumber === 'string' && UINT.test(cutoff.blockNumber)
      && typeof cutoff.blockHash === 'string' && BLOCK_HASH.test(cutoff.blockHash)
      && typeof expense?.participantGasCostWei === 'string' && UINT.test(expense.participantGasCostWei)
      && typeof expense?.participantAggregateGasUsdcUnits === 'string' && UINT.test(expense.participantAggregateGasUsdcUnits)
      && typeof budget?.budgetUsdcUnits === 'string' && UINT.test(budget.budgetUsdcUnits)
      && budget?.headroomPercent === 100 && typeof reserve?.reserveFloorWei === 'string' && UINT.test(reserve.reserveFloorWei)
      && reserve?.satisfied === true && typeof deadline?.deadlineSeconds === 'number' && deadline.deadlineSeconds > 0
      && value.releaseReadiness === 'blocked' && value.candidateDoesNotClaimTaskScore === true
      && typeof caseHash === 'string' && HASH.test(caseHash) && canonicalSha256(candidateBody) === caseHash
      ? value : null;
  }
  const swap = isRecord(value.swap) ? value.swap : null;
  const snapshots = isRecord(value.snapshots) ? value.snapshots : null;
  return value.schemaVersion === 'bts-reverse-swap-probe/v1'
    && value.classification === 'selected_executor_reverse_swap_capture_not_bts_acceptance'
    && value.status === 'captured' && typeof swap?.transactionHash === 'string'
    && /^0x[0-9a-f]{64}$/i.test(swap.transactionHash) && swap.status === 'success'
    && swap.inputAssetId === 'USDC' && swap.outputAssetId === 'WETH' && snapshots !== null
    ? value : null;
}

const TASK_BLOCKERS: Record<BtsTaskId, string[]> = {
  S1: ['task_case_identity_and_objective_not_pinned'],
  S2: ['answer_reference_not_bound_to_an_admitted_task_result'],
  S3: ['answer_reference_not_bound_to_an_admitted_task_result'],
  S4: ['allowance_revocation_without_principal_movement_not_captured'],
  M1: ['operating_expense_budget_not_pinned'],
  M2: ['operating_expense_budget_not_pinned', 'purchase_not_bound_to_an_admitted_task_cutoff'],
  M3: ['native_eth_output_and_quote_derived_minimum_not_captured'],
  M4: ['task_bound_quote_and_initial_allowance_scope_not_pinned'],
  H1: ['candidate_profile_not_an_activated_case_manifest', 'run_bound_cutoff_and_evaluator_observation_missing'],
  H2: ['candidate_profile_not_an_activated_case_manifest', 'run_bound_cutoff_and_evaluator_observation_missing'],
  H3: ['ranked_only_route_selection_reference_path_not_captured'],
  U1: ['complete_allocation_payout_data_and_permission_objective_not_pinned'],
};

function taskCaptureIds(taskId: BtsTaskId, captures: readonly PrimitiveCapture[], valid: ReadonlyMap<string, Record<string, unknown>>): PrimitiveCapture[] {
  const ids: PrimitiveCapture['captureId'][] = taskId === 'S1' ? ['s1-transfer']
    : taskId === 'S2' ? ['s2-readonly-offer']
      : taskId === 'S3' ? ['s3-readonly-catalog']
      : taskId === 'M1' ? ['m1-single-purchase']
        : taskId === 'M2' ? ['m2-minimum-purchase']
      : taskId === 'H1' ? ['resource-catalog']
        : taskId === 'H2' ? ['h2-exact-payouts']
      : taskId === 'M3' || taskId === 'M4' ? ['reverse-swap'] : [];
  return captures.filter((capture) => ids.includes(capture.captureId) && valid.has(capture.captureId));
}

export function buildTaskReferenceCaseIndex(input: {
  captures: readonly PrimitiveCapture[];
  dataComponents?: readonly DataComponentProjection[];
}): TaskReferenceCaseIndex {
  const valid = new Map<string, Record<string, unknown>>();
  for (const capture of input.captures) {
    if (valid.has(capture.captureId)) throw new Error('task_reference_duplicate_capture_id');
    const artifactSetValid = capture.artifacts.length > 0
      && capture.artifacts.every((artifact) => typeof artifact.path === 'string' && artifact.path.length > 0
        && !artifact.path.startsWith('/') && !artifact.path.split('/').some((part) => part === '' || part === '.' || part === '..')
        && HASH.test(artifact.sha256) && typeof artifact.boundary === 'string' && artifact.boundary.length > 0)
      && capture.artifacts.some((artifact) => artifact.boundary === 'actual-tool-http');
    const value = artifactSetValid ? captureValue(capture) : null;
    if (value) valid.set(capture.captureId, value);
  }
  const captures = input.captures.map((capture) => {
    const value = valid.get(capture.captureId);
    return {
      captureId: capture.captureId,
      status: value ? 'observed' as const : 'unavailable' as const,
      captureSha256: value ? canonicalSha256(value) : null,
      artifacts: capture.artifacts.map((artifact) => ({ ...artifact })),
      ...(capture.errorCode ? { errorCode: capture.errorCode } : {}),
    };
  });
  const observedCaptureIds = captures.filter((capture) => capture.status === 'observed').map((capture) => capture.captureId);
  const cases = BTS_TASK_ORDER.map((taskId): TaskReferenceCaseEntry => {
    const related = taskCaptureIds(taskId, input.captures, valid);
    const evidence = related.flatMap((capture) => capture.artifacts);
    const relatedValue = related.length ? valid.get(related[0]!.captureId) ?? null : null;
    const h1CandidateRaw = relatedValue && isRecord(relatedValue.h1ObjectiveCandidate)
      ? relatedValue.h1ObjectiveCandidate
      : null;
    const h1CandidateBody = h1CandidateRaw ? { ...h1CandidateRaw } : null;
    const h1CandidateHash = h1CandidateBody && typeof h1CandidateBody.caseHash === 'string' ? h1CandidateBody.caseHash : null;
    if (h1CandidateBody) delete h1CandidateBody.caseHash;
    const h1CandidateComponents = Array.isArray(h1CandidateRaw?.components) ? h1CandidateRaw.components.filter(isRecord) : [];
    const h1CandidateIds = h1CandidateComponents.map((item) => item.resourceId);
    const h1CandidateBudget = isRecord(h1CandidateRaw?.budgetProfile) ? h1CandidateRaw.budgetProfile : null;
    const h1CandidateDeadline = isRecord(h1CandidateRaw?.deadlineProfile) ? h1CandidateRaw.deadlineProfile : null;
    const h1Candidate = h1CandidateRaw && h1CandidateBody && h1CandidateHash
      && h1CandidateRaw.schemaVersion === 'bts-h1-observed-case-inputs/v1'
      && h1CandidateRaw.taskId === 'H1' && h1CandidateRaw.status === 'observed_candidate'
      && h1CandidateRaw.classification === 'local_reference_profile_candidate_not_release_manifest'
      && h1CandidateRaw.requiredComponentCount === 2 && h1CandidateComponents.length === 2
      && h1CandidateIds.every((id) => typeof id === 'string') && new Set(h1CandidateIds).size === 2
      && typeof h1CandidateBudget?.budgetUsdcUnits === 'string' && UINT.test(h1CandidateBudget.budgetUsdcUnits)
      && h1CandidateBudget.headroomPercent === 100
      && typeof h1CandidateDeadline?.deadlineSeconds === 'number' && h1CandidateDeadline.deadlineSeconds > 0
      && canonicalSha256(h1CandidateBody) === h1CandidateHash
      ? h1CandidateRaw
      : null;
    const h1ComponentValues = Array.isArray(h1Candidate?.components) ? h1Candidate.components : [];
    const observedComponents = h1ComponentValues.flatMap((item) => {
      if (!isRecord(item) || !isRecord(item.dataComponent)) return [];
      return [item.dataComponent as unknown as DataComponentProjection];
    });
    const m1Component = relatedValue && isRecord(relatedValue.component) ? [relatedValue.component as DataComponentProjection] : [];
    const m2Delivery = relatedValue && isRecord(relatedValue.delivery) ? relatedValue.delivery : null;
    const m2Component = m2Delivery && isRecord(m2Delivery.component) ? [m2Delivery.component as DataComponentProjection] : [];
    const components = taskId === 'M1' ? m1Component : taskId === 'H1' ? observedComponents : [];
    if (taskId === 'M2') components.push(...m2Component);
    const blockers = [...TASK_BLOCKERS[taskId]];
    // Capturing an envelope proves a byte-bound component identity, not a full
    // task case, payment policy, reference path, or release approval.
    if ((taskId === 'M1' || taskId === 'H1') && components.length === 0) blockers.push('validated_delivery_envelope_not_observed');
    if (taskId === 'H1' && !h1Candidate) blockers.push('two_component_same_generation_case_candidate_unavailable');
    if (taskId === 'H2' && relatedValue === null) blockers.push('two_exact_payout_same_generation_case_candidate_unavailable');
    if (taskId === 'M3') blockers.push('observed_swap_output_is_weth_not_native_eth');
    return {
      taskId,
      evidenceStatus: related.length ? 'observed' : 'not_observed',
      releaseReadiness: 'blocked',
      primitiveCaptureIds: related.map((capture) => capture.captureId),
      evidence,
      dataComponents: components,
      objectiveCandidate: taskId === 'H1' ? h1Candidate
        : taskId === 'H2' ? relatedValue
        : relatedValue && isRecord(relatedValue.objectiveCandidate)
        ? relatedValue.objectiveCandidate
        : relatedValue && isRecord(relatedValue.taskCaseInputs) ? relatedValue.taskCaseInputs : null,
      blockers,
    };
  });
  return {
    schemaVersion: 'bts-task-reference-cases/v1',
    classification: 'local-fork-public-tool-evidence_not_release_manifest',
    releaseReadiness: 'blocked',
    taskOrder: BTS_TASK_ORDER,
    observedCaptureIds,
    captures,
    cases,
  };
}
