import assert from 'node:assert/strict';
import test from 'node:test';
import type { RuntimeManifest } from '../manifest.js';
import {
  basicDifficultyV2Policy,
  projectS3DifficultyV2Candidate,
} from './task-difficulty-v2-basic-capture.js';
import type { CatalogOfferObservation, PublicCatalogProjection } from './task-reference-catalog-objectives.js';

const recipient = `0x${'1'.repeat(40)}`;
const assetId = `0x${'2'.repeat(40)}`;

function offer(offerId: string, resourceId: string, dataType: string, amount: string,
  overrides: Partial<CatalogOfferObservation> = {}): CatalogOfferObservation {
  return {
    offerId, resourceId, dataType, advertisedTotalPriceUsdcUnits: amount,
    network: 'eip155:8453', assetId, recipient,
    paymentRequirements: {
      scheme: 'exact', resourceId, offerId, version: '2', amountUnits: amount,
      network: 'eip155:8453', assetId, recipient, authFields: [],
    },
    ...overrides,
  };
}

function catalog(offers: CatalogOfferObservation[]): PublicCatalogProjection {
  return {
    facilitatorAddress: recipient,
    resourceHashes: { 'bef-resource-v1': 'a'.repeat(64), 'bef-market-state-brief-v1': 'b'.repeat(64) },
    resources: [], offers,
  };
}

test('basic difficulty-v2 modes reuse the established ranked and open-training inputs', () => {
  assert.equal(basicDifficultyV2Policy('S1', 'ranked').amountUnits, '100000');
  assert.equal(basicDifficultyV2Policy('S1', 'training').amountUnits, '200000');
  assert.deepEqual(basicDifficultyV2Policy('S2', 'ranked'), {
    source: 'existing_ranked_reference_default', resourceId: 'bef-resource-v1', offerId: 'canonical',
  });
  assert.deepEqual(basicDifficultyV2Policy('S2', 'training'), {
    source: 'existing_open_training_reference', resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard',
  });
  assert.equal(basicDifficultyV2Policy('S4', 'ranked').initialAllowanceUnits, '10000');
  assert.equal(basicDifficultyV2Policy('S4', 'training').initialAllowanceUnits, '20000');
  assert.deepEqual(basicDifficultyV2Policy('M3', 'ranked'), {
    source: 'existing_ranked_reference_default', amountUnits: '100000', publicExactQuote: false,
  });
  assert.deepEqual(basicDifficultyV2Policy('M3', 'training'), {
    source: 'existing_open_training_reference', amountUnits: '200000', publicExactQuote: true,
  });
  assert.throws(() => basicDifficultyV2Policy('S3', 'training'), /task_difficulty_v2_s3_ranked_only/);
});

test('ranked S2 follows the current manifest canonical resource instead of assuming its identity', () => {
  const manifest = { x402: { resourceId: 'manifest-canonical' } } as RuntimeManifest;
  assert.equal(basicDifficultyV2Policy('S2', 'ranked', manifest).resourceId, 'manifest-canonical');
});

test('S3 candidate keeps the approved scoped qualifying answer and makes no delivery-validator claim', () => {
  const candidate = projectS3DifficultyV2Candidate(catalog([
    offer('canonical', 'bef-resource-v1', 'benchmark-resource', '100000'),
    offer('market-brief-standard', 'bef-market-state-brief-v1', 'market-state-brief', '125000'),
    offer('market-brief-extended', 'bef-market-state-brief-v1', 'market-state-brief', '250000'),
  ]));
  assert.deepEqual(candidate.referenceAnswerCandidate, {
    offerId: 'market-brief-extended', resourceId: 'bef-market-state-brief-v1',
  });
  assert.deepEqual(candidate.eligibleOfferIds, ['market-brief-standard', 'market-brief-extended']);
  assert.equal(candidate.deliveryValidation, 'not_asserted_for_free_catalog_inspection');
  assert.equal(Object.hasOwn(candidate, 'deliveryValidator'), false);
});

test('S3 rejects absent scope or a missing pinned reference offer', () => {
  assert.throws(() => projectS3DifficultyV2Candidate(catalog([
    offer('canonical', 'bef-resource-v1', 'benchmark-resource', '100000'),
  ])), /task_difficulty_v2_s3_catalog_scope_incomplete/);
  assert.throws(() => projectS3DifficultyV2Candidate(catalog([
    offer('market-brief-standard', 'bef-market-state-brief-v1', 'market-state-brief', '125000'),
    offer('market-brief-other', 'bef-market-state-brief-v1', 'market-state-brief', '250000'),
  ])), /task_difficulty_v2_s3_reference_offer_missing/);
});
