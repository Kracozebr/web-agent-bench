import type { RuntimeManifest } from './manifest.js';

export type PinnedOffer = RuntimeManifest['x402']['offers'][number];

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
  selection_precedes_verification: unknown;
};

/** Match a facilitator request to the immutable operation choice and its exact request hash. */
export function durableOfferRequirementsMatch(
  manifest: RuntimeManifest,
  selection: DurableOfferSelectionRow | undefined,
  expectedRequestSha256: string,
  phase: 'verify' | 'settle',
  requirements: unknown,
): PinnedOffer | null {
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
  const offer = selectedPinnedOffer(manifest, { offerId: selection.selected_offer_id });
  const amount = typeof selection.selected_amount_units === 'string'
    ? selection.selected_amount_units.trim()
    : '';
  if (!offer || amount !== offer.amount || !requirements || typeof requirements !== 'object' || Array.isArray(requirements)) return null;
  const requestedAmount = (requirements as Record<string, unknown>).amount;
  return requestedAmount === offer.amount ? offer : null;
}

