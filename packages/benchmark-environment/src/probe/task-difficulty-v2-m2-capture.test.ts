import assert from 'node:assert/strict';
import test from 'node:test';
import type { CatalogOfferObservation, PublicCatalogProjection } from './task-reference-catalog-objectives.js';
import { selectM2DifficultyV2MinimumOffer } from './task-difficulty-v2-m2-capture.js';

const recipient = `0x${'1'.repeat(40)}`;
const assetId = `0x${'2'.repeat(40)}`;

function offer(offerId: string, amount: string, overrides: Partial<CatalogOfferObservation> = {}): CatalogOfferObservation {
  return {
    offerId,
    resourceId: 'bef-market-state-brief-v1',
    dataType: 'market-state-brief',
    advertisedTotalPriceUsdcUnits: amount,
    network: 'eip155:8453',
    assetId,
    recipient,
    paymentRequirements: {
      scheme: 'exact', resourceId: 'bef-market-state-brief-v1', offerId, version: '2',
      amountUnits: amount, network: 'eip155:8453', assetId, recipient, authFields: [],
    },
    ...overrides,
  };
}

function catalog(offers: CatalogOfferObservation[]): PublicCatalogProjection {
  return {
    facilitatorAddress: recipient,
    resourceHashes: { 'bef-market-state-brief-v1': 'a'.repeat(64) },
    resources: [],
    offers,
  };
}

test('M2 selects the lowest pinned market-state-brief offer from the observed catalog order', () => {
  const candidate = selectM2DifficultyV2MinimumOffer(catalog([
    offer('market-brief-standard', '125000'),
    offer('market-brief-economy', '75000'),
    offer('other-resource', '10000', { dataType: 'benchmark-resource', resourceId: 'bef-resource-v1' }),
  ]));
  assert.equal(candidate.offerId, 'market-brief-economy');
  assert.equal(candidate.resourceId, 'bef-market-state-brief-v1');
  assert.equal(candidate.advertisedTotalPriceUsdcUnits, '75000');
});

test('M2 rejects an incomplete or nonuniform qualifying offer set', () => {
  assert.throws(() => selectM2DifficultyV2MinimumOffer(catalog([offer('only-one', '75000')])),
    /task_difficulty_v2_m2_qualifying_catalog_invalid/);
  assert.throws(() => selectM2DifficultyV2MinimumOffer(catalog([
    offer('same-price-a', '75000'), offer('same-price-b', '75000'),
  ])), /task_difficulty_v2_m2_qualifying_prices_not_distinct/);
  assert.throws(() => selectM2DifficultyV2MinimumOffer(catalog([
    offer('market-brief-a', '75000'), offer('market-brief-b', '125000', { recipient: `0x${'3'.repeat(40)}` }),
  ])), /task_difficulty_v2_m2_qualifying_catalog_invalid/);
});
