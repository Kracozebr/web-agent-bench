import assert from 'node:assert/strict';
import test from 'node:test';
import type { PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { generatePrivateKey } from 'viem/accounts';
import {
  OWNER_X402_SIGNER_SDK_VERSIONS,
  createEphemeralX402TaskSigner,
  findPinnedResourceOffer,
  hasPaymentChallengeHeader,
  paymentRequirementMatchesPins,
  pinnedOfferResponseMatches,
  type PinnedX402Policy,
  type PinnedX402Resource,
} from './task-action-x402.js';
import { pinnedPurchaseDeliveryMatches, privateAnvilHealthMatches, safeMeasurementProjection } from './bef-task-executor.js';
import { canonicalTaskJson } from './task-release.js';
import { createHash } from 'node:crypto';

const manifestHash = 'a'.repeat(64);
const facilitator = '0x2222222222222222222222222222222222222222';
const payer = '0x1111111111111111111111111111111111111111';
const resource: PinnedX402Resource = {
  resourceId: 'bef-market-state-brief-v1',
  resourceSha256: 'b'.repeat(64),
  contentType: 'application/json',
  dataType: 'market-state-brief',
  schema: 'web-agent-bench/market-state-brief/v1',
  provenance: {
    classification: 'synthetic-benchmark-fixture',
    boundary: 'private acceptance environment',
    source: 'repository-authored deterministic fixture',
  },
  offers: [
    { id: 'market-brief-standard', amount: '125000' },
    { id: 'market-brief-extended', amount: '250000' },
  ],
};
const policy: PinnedX402Policy = {
  manifestSha256: manifestHash,
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  assetTransferMethod: 'eip3009',
  eip712Domain: { name: 'USD Coin', version: '2' },
  maxTimeoutSeconds: 120,
  sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.47.4' },
  localAnvil: {
    identity: 'private-anvil-fork', chainId: 8453, anvilVersion: '1.8.6',
    executionNetwork: 'ethereum', hardFork: 'prague', forkBlockNumber: '0x32871b4', forkBlockHash: `0x${'c'.repeat(64)}`,
  },
  resources: [resource],
};

const req: PaymentRequirements = {
  scheme: 'exact', network: 'eip155:8453', asset: policy.asset, amount: '125000', payTo: facilitator,
  maxTimeoutSeconds: 120,
  extra: { assetTransferMethod: 'eip3009', paymentFlow: 'authorization', name: 'USD Coin', version: '2' },
};
const declaration: PaymentRequired = {
  x402Version: 2,
  resource: { url: 'http://localhost/tools/bef-env-a/purchase', mimeType: 'application/json' },
  accepts: [req],
};
const command = { resourceId: resource.resourceId, offerId: resource.offers[0]!.id };
const payment = (amount: string) => ({
  scheme: 'exact', network: 'eip155:8453', asset: policy.asset, amount, payTo: facilitator, transferMethod: 'eip3009',
});

test('requires exact manifest resource and offer pins plus private local fork identity', () => {
  assert.deepEqual(OWNER_X402_SIGNER_SDK_VERSIONS, { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' });
  assert.deepEqual(findPinnedResourceOffer(policy, command.resourceId, command.offerId), {
    resource, offer: resource.offers[0],
  });
  assert.equal(findPinnedResourceOffer(policy, 'other-resource', command.offerId), null);
  assert.equal(findPinnedResourceOffer({ ...policy, localAnvil: { ...policy.localAnvil, forkBlockHash: 'c'.repeat(64) } },
    command.resourceId, command.offerId), null);
  assert.equal(findPinnedResourceOffer({ ...policy, localAnvil: { ...policy.localAnvil, identity: 'base-mainnet' as never } },
    command.resourceId, command.offerId), null);
  assert.equal(findPinnedResourceOffer({ ...policy, sdkVersions: { ...policy.sdkVersions, core: '3.0.0' } },
    command.resourceId, command.offerId), null);
});

test('requires pinned Anvil build, local fork block, facilitator and BEF SDK versions', () => {
  const health = {
    boundary: 'benchmark-environment-api' as const, manifestSha256: manifestHash,
    applicationSourceSha256: 'd'.repeat(64), envId: 'bef-env-a', facilitatorAddress: facilitator,
    anvil: {
      clientVersion: 'anvil/v1.8.6', chainId: '0x2105', executionNetwork: 'ethereum', hardFork: 'prague',
      forkBlockNumber: '0x32871b4', forkBlockHash: policy.localAnvil.forkBlockHash,
    },
    sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.47.4' },
  };
  assert.equal(privateAnvilHealthMatches(health, policy), true);
  assert.equal(privateAnvilHealthMatches({ ...health, anvil: { ...health.anvil, forkBlockHash: `0x${'e'.repeat(64)}` } }, policy), false);
  assert.equal(privateAnvilHealthMatches({ ...health, anvil: { ...health.anvil, clientVersion: 'geth/v1.0' } }, policy), false);
  assert.equal(privateAnvilHealthMatches({ ...health, sdkVersions: { ...health.sdkVersions, core: '2.27.0' } }, policy), false);
});

test('validates offer provenance independent of JSON key order and binds every advertised amount', () => {
  const body = {
    resourceId: resource.resourceId, resourceSha256: resource.resourceSha256, contentType: resource.contentType,
    dataType: resource.dataType, schema: resource.schema,
    provenance: { source: resource.provenance!.source, classification: resource.provenance!.classification,
      boundary: resource.provenance!.boundary },
    payment: payment('125000'),
    offers: resource.offers.map((offer) => ({ id: offer.id, payment: payment(offer.amount) })),
    freeInspection: true, deliveryState: 'not_delivered',
  };
  assert.equal(pinnedOfferResponseMatches({ body, command, pinnedResource: resource, pinnedOffer: resource.offers[0]!, policy, facilitatorAddress: facilitator }), true);
  assert.equal(pinnedOfferResponseMatches({
    body: { ...body, provenance: { ...body.provenance, source: 'caller supplied' } },
    command, pinnedResource: resource, pinnedOffer: resource.offers[0]!, policy, facilitatorAddress: facilitator,
  }), false);
  assert.equal(pinnedOfferResponseMatches({
    body: { ...body, offers: [{ id: resource.offers[0]!.id, payment: payment('125001') }, body.offers[1]] },
    command, pinnedResource: resource, pinnedOffer: resource.offers[0]!, policy, facilitatorAddress: facilitator,
  }), false);
});

test('accepts only the exact localhost purchase challenge and pinned authorization requirement', () => {
  assert.equal(paymentRequirementMatchesPins({
    declaration, expectedResourceId: command.resourceId, expectedOffer: resource.offers[0]!, policy,
    facilitatorAddress: facilitator, expectedPath: '/tools/bef-env-a/purchase',
  }), req);
  assert.equal(paymentRequirementMatchesPins({
    declaration: { ...declaration, resource: { url: 'https://mainnet.example/tools/bef-env-a/purchase' } },
    expectedResourceId: command.resourceId, expectedOffer: resource.offers[0]!, policy,
    facilitatorAddress: facilitator, expectedPath: '/tools/bef-env-a/purchase',
  }), null);
  assert.equal(paymentRequirementMatchesPins({
    declaration: { ...declaration, accepts: [{ ...req, amount: '1' }] },
    expectedResourceId: command.resourceId, expectedOffer: resource.offers[0]!, policy,
    facilitatorAddress: facilitator, expectedPath: '/tools/bef-env-a/purchase',
  }), null);
  assert.equal(paymentRequirementMatchesPins({
    declaration: { ...declaration, accepts: [{ ...req, extra: { ...req.extra, unexpected: true } }] },
    expectedResourceId: command.resourceId, expectedOffer: resource.offers[0]!, policy,
    facilitatorAddress: facilitator, expectedPath: '/tools/bef-env-a/purchase',
  }), null);
});

test('creates one exact-offer SDK authorization in memory without making a network request', async () => {
  const signer = createEphemeralX402TaskSigner(generatePrivateKey(), 'eip155:8453');
  assert.match(signer.payerAddress, /^0x[0-9a-f]{40}$/i);
  assert.equal(hasPaymentChallengeHeader({ 'Payment-Required': 'ephemeral-challenge-bytes' }), true);
  assert.equal(hasPaymentChallengeHeader({}), false);
  const requirements = paymentRequirementMatchesPins({
    declaration, expectedResourceId: command.resourceId, expectedOffer: resource.offers[0]!, policy,
    facilitatorAddress: facilitator, expectedPath: '/tools/bef-env-a/purchase',
  });
  assert.ok(requirements);
  const authorization = await signer.createAuthorization(declaration, requirements);
  assert.equal(Object.keys(authorization).length, 1);
  assert.ok(Object.keys(authorization).every((key) => ['payment-signature', 'x-payment'].includes(key)));
  assert.ok(Object.values(authorization).every((value) => value.length >= 16));
});

test('retains paid content only after exact manifest-byte and structured-content validation', () => {
  const content = { symbol: 'WETH', amount: '12' };
  const bytes = Buffer.from(canonicalTaskJson(content), 'utf8');
  const resourceSha256 = createHash('sha256').update(bytes).digest('hex');
  const operationId = '6f95c91f-e34e-4758-b2a8-921f740c17ab';
  const body = {
    operationId, resourceId: resource.resourceId, contentType: 'application/json', contentHash: resourceSha256,
    contentBytes: bytes.toString('base64'), content,
  };
  assert.equal(pinnedPurchaseDeliveryMatches({ body, resourceId: resource.resourceId, resourceSha256,
    contentType: 'application/json', operationId }), true);
  assert.equal(pinnedPurchaseDeliveryMatches({ body: { ...body, resourceId: 'other-resource' }, resourceId: resource.resourceId,
    resourceSha256, contentType: 'application/json', operationId }), false);
  assert.equal(pinnedPurchaseDeliveryMatches({ body: { ...body, content: { symbol: 'WETH', amount: '13' } },
    resourceId: resource.resourceId, resourceSha256, contentType: 'application/json', operationId }), false);

  const hidden = safeMeasurementProjection(body, 'a-run-token-that-is-never-stored-123');
  const verified = safeMeasurementProjection(body, 'a-run-token-that-is-never-stored-123', true);
  assert.equal(hidden && 'contentBytes' in hidden, false);
  assert.equal(verified?.contentBytes, bytes.toString('base64'));
});
