import assert from 'node:assert/strict';
import test from 'node:test';
import type { PaymentRequired, PaymentRequirements } from '@x402/core/types';
import type { RuntimeManifest } from '../manifest.js';
import {
  createEphemeralSigner,
  createPinnedSelectedOfferPayload,
  createSignedPayload,
} from './x402.js';

const payTo = '0x2222222222222222222222222222222222222222';
const asset = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const alternateAmount = '3000000';

const requirements: PaymentRequirements = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset,
  amount: alternateAmount,
  payTo,
  maxTimeoutSeconds: 120,
  extra: {
    name: 'USD Coin',
    version: '2',
    paymentFlow: 'authorization',
    assetTransferMethod: 'eip3009',
  },
};

const declaration: PaymentRequired = {
  x402Version: 2,
  resource: { url: 'http://127.0.0.1/bef-resource-v1' },
  accepts: [requirements],
};

const manifest = {
  x402: {
    scheme: 'exact',
    network: 'eip155:8453',
    asset,
    offers: [
      { id: 'canonical', amount: '100000' },
      { id: 'task-goal-exceeded', amount: alternateAmount },
    ],
  },
  funding: { maxUsdcUnitsPerGeneration: '100000000' },
} as unknown as RuntimeManifest;

test('SC002 selected offer uses an exact SDK asset cap without changing ordinary spend controls', async () => {
  const signer = createEphemeralSigner();
  await assert.rejects(
    createSignedPayload(signer, declaration, requirements),
    /probe_x402_spend_controls_rejected_requirements/,
  );

  const signed = await createPinnedSelectedOfferPayload(
    signer, declaration, requirements, manifest, 'task-goal-exceeded',
  );
  assert.equal(signed.payload.accepted.amount, alternateAmount);
  assert.equal(signed.payload.accepted.asset.toLowerCase(), asset.toLowerCase());
  assert.equal(signed.payload.accepted.network, 'eip155:8453');

  await assert.rejects(
    createSignedPayload(signer, declaration, requirements),
    /probe_x402_spend_controls_rejected_requirements/,
  );
});

test('SC002 selected-offer signer rejects unpinned identity and amount changes before signing', async () => {
  const signer = createEphemeralSigner();
  const rejected: Array<{ offerId: string; requirements: PaymentRequirements }> = [
    { offerId: 'unlisted-offer', requirements },
    { offerId: 'canonical', requirements },
    { offerId: 'task-goal-exceeded', requirements: { ...requirements, amount: '3000001' } },
    { offerId: 'task-goal-exceeded', requirements: { ...requirements, asset: '0x4444444444444444444444444444444444444444' } },
    { offerId: 'task-goal-exceeded', requirements: { ...requirements, network: 'eip155:1' } },
  ];
  for (const item of rejected) {
    await assert.rejects(
      createPinnedSelectedOfferPayload(signer, declaration, item.requirements, manifest, item.offerId),
      /probe_x402_selected_offer_out_of_scope/,
    );
  }
});
