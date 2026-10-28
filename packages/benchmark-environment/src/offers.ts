import type { RuntimeManifest } from './manifest.js';

export type PinnedOffer = RuntimeManifest['x402']['offers'][number];
export type PinnedResource = NonNullable<RuntimeManifest['x402']['catalog']>[number];

/** Older BEF manifests keep their original single-resource root fields. */
export function pinnedResources(manifest: RuntimeManifest): PinnedResource[] {
  if (manifest.x402.catalog) return manifest.x402.catalog;
  return [{
    resourceId: manifest.x402.resourceId,
    resourcePath: manifest.x402.resourcePath,
    resourceSha256: manifest.x402.resourceSha256,
    contentType: 'application/json',
    schema: 'legacy-single-resource',
    provenance: {
      classification: 'synthetic-benchmark-fixture',
      boundary: 'private acceptance environment',
      source: 'legacy BEF pinned resource fields',
    },
    offers: manifest.x402.offers,
  }];
}

export function pinnedResource(manifest: RuntimeManifest, resourceId: unknown): PinnedResource | null {
  if (typeof resourceId !== 'string') return null;
  return pinnedResources(manifest).find((resource) => resource.resourceId === resourceId) ?? null;
}

/** Preserve the original /offer request shape by defaulting an omitted id to the root resource. */
export function resolveOfferResourceId(manifest: RuntimeManifest, requestedResourceId: unknown): unknown {
  return requestedResourceId === undefined ? manifest.x402.resourceId : requestedResourceId;
}

export type PinnedResourceOffer = { resource: PinnedResource; offer: PinnedResource['offers'][number] };

/** Resolve the immutable resource+offer pair. The request supplies identifiers only. */
export function selectedPinnedResourceOffer(manifest: RuntimeManifest, body: unknown): PinnedResourceOffer | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const value = body as Record<string, unknown>;
  const resource = pinnedResource(manifest, value.resourceId);
  if (!resource || typeof value.offerId !== 'string') return null;
  const offer = resource.offers.find((candidate) => candidate.id === value.offerId);
  return offer ? { resource, offer } : null;
}

/** Resolve only a manifest-pinned choice. Request amounts are never prices. */
export function selectedPinnedOffer(manifest: RuntimeManifest, body: unknown): PinnedOffer | null {
  const offerId = body && typeof body === 'object' && !Array.isArray(body)
    ? (body as Record<string, unknown>).offerId
    : undefined;
  if (typeof offerId !== 'string') return null;
  return manifest.x402.offers.find((offer) => offer.id === offerId) ?? null;
}

export function pinnedOfferRequirementsMatch(
  expected: { scheme: string; network: string; asset: string; amount: string; payTo: string },
  actual: unknown,
): boolean {
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
  const value = actual as Record<string, unknown>;
  return value.scheme === expected.scheme
    && value.network === expected.network
    && typeof value.asset === 'string' && value.asset.toLowerCase() === expected.asset.toLowerCase()
    && value.amount === expected.amount
    && typeof value.payTo === 'string' && value.payTo.toLowerCase() === expected.payTo.toLowerCase();
}

export type DurableOfferSelectionRow = {
  request_sha256: unknown;
  operation_kind: unknown;
  status: unknown;
  resource_variant: unknown;
  selected_offer_id: unknown;
  selected_amount_units: unknown;
  selected_resource_id?: unknown;
  selected_resource_sha256?: unknown;
  selection_precedes_verification: unknown;
};

/** Match a facilitator request to the immutable operation choice and its exact request hash. */
export function durableOfferRequirementsMatch(
  manifest: RuntimeManifest,
  selection: DurableOfferSelectionRow | undefined,
  expectedRequestSha256: string,
  phase: 'verify' | 'settle',
  requirements: unknown,
): PinnedResourceOffer['offer'] | null {
  if (!selection || !/^[0-9a-f]{64}$/.test(expectedRequestSha256)) return null;
  const recordedRequestHash = typeof selection.request_sha256 === 'string'
    ? selection.request_sha256.trim().toLowerCase()
    : '';
  if (recordedRequestHash !== expectedRequestSha256
    || selection.operation_kind !== 'purchase'
    || selection.selection_precedes_verification !== true) return null;
  const phaseStatusIsValid = phase === 'verify'
    ? selection.status === 'verifying'
      || (selection.status === 'awaiting_payment' && selection.resource_variant === 'verification_without_receipt')
    : selection.status === 'verifying' || selection.status === 'settling';
  if (!phaseStatusIsValid) return null;
  const resourceId = typeof selection.selected_resource_id === 'string'
    ? selection.selected_resource_id : manifest.x402.resourceId;
  const selected = selectedPinnedResourceOffer(manifest, { resourceId, offerId: selection.selected_offer_id });
  const amount = typeof selection.selected_amount_units === 'string'
    ? selection.selected_amount_units.trim()
    : '';
  const resourceHash = typeof selection.selected_resource_sha256 === 'string'
    ? selection.selected_resource_sha256.trim().toLowerCase() : selected?.resource.resourceSha256.toLowerCase();
  if (!selected || resourceHash !== selected.resource.resourceSha256.toLowerCase()
    || amount !== selected.offer.amount || !requirements || typeof requirements !== 'object' || Array.isArray(requirements)) return null;
  const requestedAmount = (requirements as Record<string, unknown>).amount;
  return requestedAmount === selected.offer.amount ? selected.offer : null;
}

