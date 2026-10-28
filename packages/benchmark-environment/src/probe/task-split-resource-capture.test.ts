import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import type { RuntimeManifest } from '../manifest.js';
import { projectSplitOfferRead } from './task-split-resource-capture.js';

const facilitatorAddress = `0x${'1'.repeat(40)}`;

async function readManifest(): Promise<RuntimeManifest> {
  const bytes = await readFile(new URL('../../../../infrastructure/benchmark-environment/manifest.json', import.meta.url));
  return JSON.parse(bytes.toString('utf8')) as RuntimeManifest;
}

function offerResponse(manifest: RuntimeManifest, resourceId: string) {
  const resource = manifest.x402.catalog!.find((item) => item.resourceId === resourceId)!;
  const offers = resource.offers.map((offer) => ({
    id: offer.id,
    payment: {
      scheme: manifest.x402.scheme,
      network: manifest.x402.network,
      asset: manifest.x402.asset,
      amount: offer.amount,
      payTo: facilitatorAddress,
      transferMethod: manifest.x402.assetTransferMethod,
    },
  }));
  return {
    operationId: '68f12eb8-2cf1-49a8-87df-55ed72380919',
    readHandle: { kind: 'offer', operationId: '68f12eb8-2cf1-49a8-87df-55ed72380919' },
    resourceId: resource.resourceId,
    resourceSha256: resource.resourceSha256,
    contentType: resource.contentType,
    ...(resource.dataType === undefined ? {} : { dataType: resource.dataType }),
    schema: resource.schema,
    provenance: resource.provenance,
    payment: offers[0]!.payment,
    offers,
    freeInspection: true,
    deliveryState: 'not_delivered',
  };
}

test('split offer projection takes accepted terms from the public read and binds every offer to manifest pins', async () => {
  const manifest = await readManifest();
  const resource = manifest.x402.catalog![0]!;
  const response = offerResponse(manifest, resource.resourceId);
  const projected = projectSplitOfferRead({ response, manifest, facilitatorAddress, resourceId: resource.resourceId });

  assert.equal(projected.length, resource.offers.length);
  assert.deepEqual(projected.map(({ offerId }) => offerId), resource.offers.map(({ id }) => id));
  assert.deepEqual(projected[0]!.acceptedTerms, { ...response.payment, asset: response.payment.asset.toLowerCase() });
});

test('split offer projection rejects a public amount that differs from the manifest', async () => {
  const manifest = await readManifest();
  const resource = manifest.x402.catalog![0]!;
  const response = offerResponse(manifest, resource.resourceId);
  const offers = response.offers.map((offer, index) => index === 0
    ? { ...offer, payment: { ...offer.payment, amount: '999999' } }
    : offer);
  await assert.rejects(async () => projectSplitOfferRead({
    response: { ...response, offers, payment: offers[0]!.payment }, manifest, facilitatorAddress, resourceId: resource.resourceId,
  }), /task_split_public_payment_terms_manifest_mismatch/);
});

test('split offer projection rejects resource, schema, provenance, and facilitator substitution', async () => {
  const manifest = await readManifest();
  const resource = manifest.x402.catalog![0]!;
  const response = offerResponse(manifest, resource.resourceId);
  const cases: Array<[string, unknown, string]> = [
    ['resource', { ...response, resourceSha256: 'f'.repeat(64) }, 'task_split_public_offer_resource_manifest_mismatch'],
    ['schema', { ...response, schema: 'attacker/schema-v1' }, 'task_split_public_offer_resource_manifest_mismatch'],
    ['provenance', { ...response, provenance: { ...response.provenance, source: 'unapproved' } }, 'task_split_public_offer_resource_manifest_mismatch'],
    ['facilitator', { ...response, payment: { ...response.payment, payTo: `0x${'2'.repeat(40)}` } }, 'task_split_public_payment_terms_manifest_mismatch'],
  ];
  for (const [label, candidate, code] of cases) {
    assert.throws(() => projectSplitOfferRead({
      response: candidate, manifest, facilitatorAddress, resourceId: resource.resourceId,
    }), new RegExp(code), label);
  }
});

test('split offer projection rejects a caller requested resource that was not the returned resource', async () => {
  const manifest = await readManifest();
  const resource = manifest.x402.catalog![0]!;
  const response = offerResponse(manifest, resource.resourceId);
  await assert.rejects(async () => projectSplitOfferRead({
    response, manifest, facilitatorAddress, resourceId: manifest.x402.catalog![1]!.resourceId,
  }), /task_split_public_offer_resource_manifest_mismatch/);
});
