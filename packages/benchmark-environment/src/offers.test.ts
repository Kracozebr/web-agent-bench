import assert from 'node:assert/strict';
import test from 'node:test';
import { durableOfferRequirementsMatch, selectedPinnedOffer, selectedPinnedResourceOffer, pinnedOfferRequirementsMatch, resolveOfferResourceId } from './offers.js';
import type { RuntimeManifest } from './manifest.js';

const manifest = {
  x402: {
    resourceId: 'bef-resource-v1',
    resourcePath: 'infrastructure/benchmark-environment/resource.json',
    resourceSha256: 'a'.repeat(64),
    offers: [
      { id: 'canonical', amount: '100000' },
      { id: 'task-goal-exceeded', amount: '3000000' },
    ],
    catalog: [
      {
        resourceId: 'bef-resource-v1', resourcePath: 'infrastructure/benchmark-environment/resource.json', resourceSha256: 'a'.repeat(64),
        contentType: 'application/json', schema: 'web-agent-bench/resource/v1',
        provenance: { classification: 'synthetic-benchmark-fixture', boundary: 'private acceptance environment', source: 'test' },
        offers: [{ id: 'canonical', amount: '100000' }, { id: 'task-goal-exceeded', amount: '3000000' }],
      },
      {
        resourceId: 'bef-market-state-brief-v1', resourcePath: 'infrastructure/benchmark-environment/resources/market-state-brief.json', resourceSha256: 'b'.repeat(64),
        contentType: 'application/json', schema: 'web-agent-bench/market-state-brief/v1',
        provenance: { classification: 'synthetic-benchmark-fixture', boundary: 'private acceptance environment', source: 'test' },
        offers: [{ id: 'market-brief-standard', amount: '125000' }],
      },
    ],
  },
} as unknown as RuntimeManifest;

test('SC002 requires an explicit pinned offer and never accepts caller-supplied prices', () => {
  assert.equal(selectedPinnedOffer(manifest, { resourceId: 'bef-resource-v1' }), null);
  assert.deepEqual(selectedPinnedOffer(manifest, { resourceId: 'bef-resource-v1', offerId: 'canonical' }), { id: 'canonical', amount: '100000' });
  assert.deepEqual(selectedPinnedOffer(manifest, { resourceId: 'bef-resource-v1', offerId: 'canonical' }), { id: 'canonical', amount: '100000' });
  assert.deepEqual(selectedPinnedOffer(manifest, { resourceId: 'bef-resource-v1', offerId: 'task-goal-exceeded' }), { id: 'task-goal-exceeded', amount: '3000000' });
  assert.equal(selectedPinnedOffer(manifest, { offerId: '0x0000000000000000000000000000000000000000' }), null);
  assert.equal(selectedPinnedOffer(manifest, { offerId: 3 }), null);
});

test('resource catalog selection binds distinct pinned offers and rejects cross-resource IDs', () => {
  assert.deepEqual(selectedPinnedResourceOffer(manifest, { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard' }), {
    resource: manifest.x402.catalog![1], offer: manifest.x402.catalog![1]!.offers[0],
  });
  assert.equal(selectedPinnedResourceOffer(manifest, { resourceId: 'bef-market-state-brief-v1', offerId: 'canonical' }), null);
  assert.equal(selectedPinnedResourceOffer(manifest, { resourceId: 'bef-unknown-resource-v1', offerId: 'market-brief-standard' }), null);
  assert.deepEqual(selectedPinnedResourceOffer(manifest, { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amount: '1' }), {
    resource: manifest.x402.catalog![1], offer: manifest.x402.catalog![1]!.offers[0],
  }, 'caller amounts are ignored; only the pinned identifiers resolve');
});

test('legacy /offer requests without a resource id remain bound to the original resource', () => {
  assert.equal(resolveOfferResourceId(manifest, undefined), 'bef-resource-v1');
  assert.equal(resolveOfferResourceId(manifest, 'bef-market-state-brief-v1'), 'bef-market-state-brief-v1');
  assert.equal(resolveOfferResourceId(manifest, null), null, 'malformed explicit values are not treated as omission');
});

test('SC002 matching binds the complete selected offer identity and never repairs amount', () => {
  const expected = { scheme: 'exact', network: 'eip155:8453', asset: '0x' + '11'.repeat(20), amount: '3000000', payTo: '0x' + '22'.repeat(20) };
  assert.equal(pinnedOfferRequirementsMatch(expected, expected), true);
  assert.equal(pinnedOfferRequirementsMatch(expected, { ...expected, amount: '100000' }), false);
  assert.equal(pinnedOfferRequirementsMatch(expected, { ...expected, asset: '0x' + '33'.repeat(20) }), false);
});

test('SC002 facilitator matching binds the durable selection, operation request hash, phase, and exact amount', () => {
  const requestSha256 = 'a'.repeat(64);
  const row = {
    request_sha256: requestSha256,
    operation_kind: 'purchase',
    status: 'verifying',
    resource_variant: 'canonical',
    selected_offer_id: 'task-goal-exceeded',
    selected_amount_units: '3000000',
    selected_resource_id: 'bef-resource-v1',
    selected_resource_sha256: 'a'.repeat(64),
    selection_precedes_verification: true,
  };
  assert.deepEqual(durableOfferRequirementsMatch(manifest, row, requestSha256, 'verify', { amount: '3000000' }),
    { id: 'task-goal-exceeded', amount: '3000000' });
  assert.equal(durableOfferRequirementsMatch(manifest, row, 'b'.repeat(64), 'verify', { amount: '3000000' }), null);
  assert.equal(durableOfferRequirementsMatch(manifest, row, requestSha256, 'verify', { amount: '100000' }), null);
  assert.equal(durableOfferRequirementsMatch(manifest, { ...row, selected_amount_units: '2000000' }, requestSha256, 'verify', { amount: '2000000' }), null);
  assert.equal(durableOfferRequirementsMatch(manifest, { ...row, selected_resource_id: 'bef-market-state-brief-v1' }, requestSha256, 'verify', { amount: '3000000' }), null,
    'a resource change cannot reuse another resource offer');
  assert.equal(durableOfferRequirementsMatch(manifest, { ...row, selected_resource_sha256: 'b'.repeat(64) }, requestSha256, 'verify', { amount: '3000000' }), null,
    'a catalog content digest change cannot reuse the persisted selection');
  assert.equal(durableOfferRequirementsMatch(manifest, { ...row, status: 'settled' }, requestSha256, 'verify', { amount: '3000000' }), null);
  assert.equal(durableOfferRequirementsMatch(manifest, { ...row, selection_precedes_verification: false }, requestSha256, 'settle', { amount: '3000000' }), null);
  const privateVerifyOnly = { ...row, status: 'awaiting_payment', resource_variant: 'verification_without_receipt' };
  assert.deepEqual(durableOfferRequirementsMatch(manifest, privateVerifyOnly, requestSha256, 'verify', { amount: '3000000' }),
    { id: 'task-goal-exceeded', amount: '3000000' });
  assert.equal(durableOfferRequirementsMatch(manifest, privateVerifyOnly, requestSha256, 'settle', { amount: '3000000' }), null);
  assert.equal(durableOfferRequirementsMatch(manifest, { ...privateVerifyOnly, resource_variant: 'canonical' }, requestSha256, 'verify', { amount: '3000000' }), null);
});

