/**
 * Candidate S3/M2 objectives projected from the pinned public catalog.
 *
 * These projections are review inputs only. They do not create a task release,
 * pin a task budget, or represent a participant answer or score.
 */
import type { RuntimeManifest } from '../manifest.js';
import type { DataComponentProjection } from './task-reference-cases.js';

type RecordValue = Record<string, unknown>;

export type CatalogOfferObservation = {
  offerId: string;
  resourceId: string;
  dataType: string;
  advertisedTotalPriceUsdcUnits: string;
  network: string;
  assetId: string;
  recipient: string;
  paymentRequirements: {
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
};

export type CatalogOfferCandidate = CatalogOfferObservation & {
  deliveryValidator: DataComponentProjection['validator'];
};

export type PublicCatalogProjection = {
  facilitatorAddress: string;
  resourceHashes: Record<string, string>;
  resources: Array<{
    resourceId: string;
    resourceSha256: string;
    contentType: string;
    dataType: string;
    schema: string;
    provenance: RecordValue;
    offers: CatalogOfferObservation[];
  }>;
  offers: CatalogOfferObservation[];
};

export type CatalogObjectiveCandidate = {
  schemaVersion: 'bts-observed-catalog-objective-candidate/v1';
  classification: 'derived_from_pinned_public_catalog_not_release_or_answer';
  taskId: 'S3' | 'M2';
  catalog: CatalogOfferCandidate[];
  required: {
    requiredDataType: string;
    maxAdvertisedTotalPriceUsdcUnits: string;
    network: string;
    assetId: string;
    recipient: string;
  };
  referenceAnswerCandidate: { offerId: string; resourceId: string };
  eligibleOfferIds: string[];
  minAdvertisedTotalPriceUsdcUnits: string;
};

function record(value: unknown): RecordValue | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : null;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as RecordValue).sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_reference_catalog_${label}_invalid`);
  return value;
}

function address(value: unknown, label: string): string {
  const parsed = requiredString(value, label);
  if (!/^0x[0-9a-f]{40}$/i.test(parsed)) throw new Error(`task_reference_catalog_${label}_invalid`);
  return parsed.toLowerCase();
}

function nonnegativeUnits(value: unknown, label: string): string {
  const parsed = requiredString(value, label);
  if (!/^(?:0|[1-9][0-9]*)$/.test(parsed)) throw new Error(`task_reference_catalog_${label}_invalid`);
  return parsed;
}

function componentMap(components: readonly DataComponentProjection[]): Map<string, DataComponentProjection> {
  const result = new Map<string, DataComponentProjection>();
  for (const component of components) {
    const existing = result.get(component.resourceId);
    if (existing) {
      if (canonicalJson(existing) !== canonicalJson(component)) throw new Error('task_reference_catalog_duplicate_delivery_component');
      continue;
    }
    result.set(component.resourceId, component);
  }
  return result;
}

/** Validate every public catalog field against the immutable BEF resource and offer pins. */
export function projectPinnedPublicCatalog(input: {
  response: unknown;
  manifest: RuntimeManifest;
}): PublicCatalogProjection {
  const response = record(input.response);
  const definitions = input.manifest.x402.catalog;
  if (!response || !definitions || response.freeInspection !== true || response.deliveryState !== 'not_delivered'
    || !Array.isArray(response.catalog) || response.catalog.length !== definitions.length) {
    throw new Error('task_reference_catalog_public_response_invalid');
  }

  const rawById = new Map<string, RecordValue>();
  for (const value of response.catalog) {
    const item = record(value);
    if (!item || typeof item.resourceId !== 'string' || rawById.has(item.resourceId)) {
      throw new Error('task_reference_catalog_resource_identity_invalid');
    }
    rawById.set(item.resourceId, item);
  }

  const resourceIds = new Set<string>();
  const offerIds = new Set<string>();
  let facilitatorAddress: string | null = null;
  const resources: PublicCatalogProjection['resources'] = [];
  for (const definition of definitions) {
    const item = rawById.get(definition.resourceId);
    if (!item || resourceIds.has(definition.resourceId) || item.resourceSha256 !== definition.resourceSha256
      || item.contentType !== definition.contentType || item.schema !== definition.schema
      || canonicalJson(item.provenance) !== canonicalJson(definition.provenance)
      || (definition.dataType === undefined ? Object.hasOwn(item, 'dataType') : item.dataType !== definition.dataType)
      || !Array.isArray(item.offers) || item.offers.length !== definition.offers.length) {
      throw new Error('task_reference_catalog_manifest_binding_mismatch');
    }
    resourceIds.add(definition.resourceId);
    const projectedOffers: CatalogOfferObservation[] = [];
    for (const [index, expected] of definition.offers.entries()) {
      const listed = record(item.offers[index]);
      const payment = record(listed?.payment);
      if (!listed || !payment || listed.id !== expected.id || offerIds.has(expected.id)
        || payment.scheme !== input.manifest.x402.scheme || payment.network !== input.manifest.x402.network
        || String(payment.asset).toLowerCase() !== input.manifest.x402.asset.toLowerCase()
        || payment.amount !== expected.amount || payment.transferMethod !== input.manifest.x402.assetTransferMethod) {
        throw new Error('task_reference_catalog_offer_binding_mismatch');
      }
      const payTo = address(payment.payTo, 'recipient');
      if (facilitatorAddress !== null && facilitatorAddress !== payTo) {
        throw new Error('task_reference_catalog_facilitator_changed');
      }
      facilitatorAddress = payTo;
      offerIds.add(expected.id);
      const assetId = address(payment.asset, 'asset');
      const authFields = [
        { name: 'assetTransferMethod', value: input.manifest.x402.assetTransferMethod },
        { name: 'paymentFlow', value: 'authorization' },
        { name: 'name', value: input.manifest.x402.eip712Domain.name },
        { name: 'version', value: input.manifest.x402.eip712Domain.version },
      ];
      projectedOffers.push({
        offerId: expected.id,
        resourceId: definition.resourceId,
        dataType: definition.dataType ?? '',
        advertisedTotalPriceUsdcUnits: nonnegativeUnits(payment.amount, 'offer_amount'),
        network: requiredString(payment.network, 'network'),
        assetId,
        recipient: payTo,
        paymentRequirements: {
          scheme: requiredString(payment.scheme, 'scheme'),
          resourceId: definition.resourceId,
          offerId: expected.id,
          version: input.manifest.x402.eip712Domain.version,
          amountUnits: expected.amount,
          network: input.manifest.x402.network,
          assetId,
          recipient: payTo,
          authFields,
        },
      });
    }
    resources.push({
      resourceId: definition.resourceId,
      resourceSha256: definition.resourceSha256,
      contentType: definition.contentType,
      dataType: definition.dataType ?? '',
      schema: definition.schema,
      provenance: definition.provenance as unknown as RecordValue,
      offers: projectedOffers,
    });
  }
  if (resourceIds.size !== definitions.length || offerIds.size !== definitions.reduce((sum, item) => sum + item.offers.length, 0)
    || facilitatorAddress === null) throw new Error('task_reference_catalog_incomplete');
  return {
    facilitatorAddress,
    resourceHashes: Object.fromEntries(resources.map((resource) => [resource.resourceId, resource.resourceSha256])),
    resources,
    offers: resources.flatMap((resource) => resource.offers),
  };
}

function withObservedDeliveryValidators(
  offers: readonly CatalogOfferObservation[],
  components: readonly DataComponentProjection[],
  resourceHashes: Readonly<Record<string, string>>,
): CatalogOfferCandidate[] {
  const byResource = componentMap(components);
  return offers.map((offer) => {
    const component = byResource.get(offer.resourceId);
    if (!component) throw new Error(`task_reference_catalog_delivery_validator_unobserved_${offer.resourceId}`);
    const expectedHash = resourceHashes[offer.resourceId];
    const requiredFields = new Set(component.validator.requiredFields.map((field) => field.name));
    const resourcePredicate = component.validator.predicates.find((predicate) => predicate.op === 'equals' && predicate.field === 'resourceId');
    const contentHashPredicate = component.validator.predicates.find((predicate) => predicate.op === 'equals' && predicate.field === 'contentHash');
    if (!expectedHash || component.resourceId !== offer.resourceId
      || component.validator.payloadSchemaVersion !== 'bef-delivery-envelope/v1'
      || !requiredFields.has('resourceId') || !requiredFields.has('contentHash') || !requiredFields.has('contentBytes')
      || resourcePredicate?.value !== offer.resourceId || contentHashPredicate?.value !== expectedHash) {
      throw new Error(`task_reference_catalog_delivery_validator_manifest_mismatch_${offer.resourceId}`);
    }
    return { ...offer, deliveryValidator: component.validator };
  });
}

function makeObjective(input: {
  taskId: 'S3' | 'M2';
  offers: readonly CatalogOfferObservation[];
  requiredDataType: string;
  maxPrice: string;
  referenceOfferId?: string;
  components: readonly DataComponentProjection[];
  resourceHashes: Readonly<Record<string, string>>;
}): CatalogObjectiveCandidate {
  if (input.offers.length < 2) throw new Error('task_reference_catalog_objective_requires_two_offers');
  const maxPrice = BigInt(nonnegativeUnits(input.maxPrice, 'maximum_price'));
  const matchingType = input.offers.filter((offer) => offer.dataType === input.requiredDataType);
  if (!matchingType.length) throw new Error('task_reference_catalog_objective_data_type_missing');
  const first = matchingType[0]!;
  const required = {
    requiredDataType: input.requiredDataType,
    maxAdvertisedTotalPriceUsdcUnits: maxPrice.toString(),
    network: first.network,
    assetId: first.assetId,
    recipient: first.recipient,
  };
  const eligible = matchingType.filter((offer) => offer.network === required.network && offer.assetId === required.assetId
    && offer.recipient.toLowerCase() === required.recipient.toLowerCase()
    && BigInt(offer.advertisedTotalPriceUsdcUnits) <= maxPrice);
  if (!eligible.length || (input.taskId === 'S3' && eligible.length === input.offers.length)) {
    throw new Error('task_reference_catalog_objective_must_have_qualifying_and_excluded_choices');
  }
  const minimum = eligible.reduce((min, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) < min
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : min, BigInt(eligible[0]!.advertisedTotalPriceUsdcUnits));
  const reference = input.referenceOfferId
    ? eligible.find((offer) => offer.offerId === input.referenceOfferId)
    : eligible.find((offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) === minimum);
  if (!reference) throw new Error('task_reference_catalog_reference_offer_not_eligible');
  return {
    schemaVersion: 'bts-observed-catalog-objective-candidate/v1',
    classification: 'derived_from_pinned_public_catalog_not_release_or_answer',
    taskId: input.taskId,
    catalog: withObservedDeliveryValidators(input.offers, input.components, input.resourceHashes),
    required,
    referenceAnswerCandidate: { offerId: reference.offerId, resourceId: reference.resourceId },
    eligibleOfferIds: eligible.map((offer) => offer.offerId),
    minAdvertisedTotalPriceUsdcUnits: minimum.toString(),
  };
}

/** S3 candidate: a caller-visible typed offer qualifies at a ceiling derived from the public catalog. */
export function projectS3CatalogObjective(input: {
  publicCatalog: PublicCatalogProjection;
  components: readonly DataComponentProjection[];
  requiredDataType?: string;
  referenceOfferId?: string;
}): CatalogObjectiveCandidate {
  const requiredDataType = input.requiredDataType ?? 'benchmark-resource';
  const typed = input.publicCatalog.offers.filter((offer) => offer.dataType === requiredDataType);
  if (typed.length < 2) throw new Error('task_reference_s3_catalog_scope_not_observed');
  const max = typed.reduce((value, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) > value
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : value, 0n);
  const referenceOfferId = input.referenceOfferId ?? typed.find((offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) === max)?.offerId;
  if (!referenceOfferId) throw new Error('task_reference_s3_reference_offer_unobserved');
  return makeObjective({
    taskId: 'S3', offers: input.publicCatalog.offers, requiredDataType, maxPrice: max.toString(),
    referenceOfferId,
    components: input.components,
    resourceHashes: input.publicCatalog.resourceHashes,
  });
}

/** M2 candidate: all observed market briefs qualify, with a strictly distinct advertised minimum. */
export function projectM2CatalogObjective(input: {
  publicCatalog: PublicCatalogProjection;
  components: readonly DataComponentProjection[];
  requiredDataType?: string;
}): CatalogObjectiveCandidate {
  const requiredDataType = input.requiredDataType ?? 'market-state-brief';
  const scoped = input.publicCatalog.offers.filter((offer) => offer.dataType === requiredDataType);
  if (scoped.length < 2) throw new Error('task_reference_m2_qualifying_catalog_incomplete');
  const prices = new Set(scoped.map((offer) => offer.advertisedTotalPriceUsdcUnits));
  if (prices.size < 2) throw new Error('task_reference_m2_prices_not_distinct');
  const max = scoped.reduce((value, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) > value
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : value, 0n);
  return makeObjective({
    taskId: 'M2', offers: scoped, requiredDataType, maxPrice: max.toString(),
    components: input.components,
    resourceHashes: input.publicCatalog.resourceHashes,
  });
}

/** Return only the exact lowest qualifying offer from an M2 candidate. */
export function minimumM2Offer(candidate: CatalogObjectiveCandidate): CatalogOfferCandidate {
  if (candidate.taskId !== 'M2' || candidate.eligibleOfferIds.length < 2) {
    throw new Error('task_reference_m2_candidate_invalid');
  }
  const eligible = candidate.catalog.filter((offer) => candidate.eligibleOfferIds.includes(offer.offerId));
  const minimum = BigInt(candidate.minAdvertisedTotalPriceUsdcUnits);
  const minima = eligible.filter((offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) === minimum);
  if (!minima.length) throw new Error('task_reference_m2_minimum_candidate_invalid');
  const selected = minima.find((offer) => offer.offerId === candidate.referenceAnswerCandidate.offerId);
  if (!selected) throw new Error('task_reference_m2_reference_answer_not_minimum');
  return selected;
}
