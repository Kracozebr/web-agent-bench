import assert from 'node:assert/strict';
import test from 'node:test';
import type { RuntimeManifest } from './manifest.js';
import { pinnedPaymentIdentity } from './payment-identity.js';

test('public payment identity derives only from the actual provider domain policy', () => {
  const manifest = { x402: { eip712Domain: { name: 'Merchant Test Token', version: '73' } } } as unknown as RuntimeManifest;
  assert.deepEqual(pinnedPaymentIdentity(manifest), { paymentFlow: 'authorization', name: 'Merchant Test Token', version: '73' });
  Object.assign(manifest.x402.eip712Domain, { name: 'Other Public Token', version: '74' });
  assert.deepEqual(pinnedPaymentIdentity(manifest), { paymentFlow: 'authorization', name: 'Other Public Token', version: '74' });
  assert.deepEqual(Object.keys(pinnedPaymentIdentity(manifest)).sort(), ['name', 'paymentFlow', 'version']);
});
