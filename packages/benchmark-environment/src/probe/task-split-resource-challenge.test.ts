import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { GenerationSession } from './runner.js';
import {
  buildSplitRetrieveHeaders,
  deferredPaymentReceiptHashMatches,
  splitPaymentChallengeResourcePath,
} from './task-split-resource-capture.js';

const expectedPath = '/tools/bef-env-a/pay';

test('split pay challenge accepts the SDK v2 resource object URL', () => {
  const declaration = {
    x402Version: 2,
    resource: {
      url: `http://localhost${expectedPath}`,
      description: 'Pinned local benchmark resource',
      mimeType: 'application/json',
    },
    accepts: [],
  };
  assert.equal(splitPaymentChallengeResourcePath(declaration, expectedPath), expectedPath);
});

test('split pay challenge rejects legacy string and unpinned resource URLs', () => {
  const invalid: Array<[unknown, RegExp]> = [
    [{ x402Version: 2, resource: `http://localhost${expectedPath}` }, /task_split_payment_challenge_invalid/],
    [{ x402Version: 2, resource: { url: 'http://attacker.invalid/tools/bef-env-a/pay' } }, /task_split_payment_challenge_resource_invalid/],
    [{ x402Version: 2, resource: { url: `http://localhost${expectedPath}?redirect=1` } }, /task_split_payment_challenge_resource_invalid/],
    [{ x402Version: 2, resource: { url: 'http://localhost/tools/bef-env-a/purchase' } }, /task_split_payment_challenge_route_mismatch/],
  ];
  for (const [candidate, expectedError] of invalid) {
    assert.throws(() => splitPaymentChallengeResourcePath(candidate, expectedPath), expectedError);
  }
});

test('split retrieve request includes the route-required idempotency key without a payment signature', () => {
  const session = {
    envId: 'bef-env-a',
    generationId: '93432b71-ae46-43c8-afec-9fe60f70c45b',
    runToken: 'unit-test-placeholder-not-a-credential',
  } as GenerationSession;
  const headers = buildSplitRetrieveHeaders(session);
  assert.equal(headers.authorization, `Bearer ${session.runToken}`);
  assert.equal(headers['X-BEF-Generation'], session.generationId);
  assert.match(headers['Idempotency-Key'] ?? '', /^[0-9a-f-]{36}$/i);
  assert.equal('payment-signature' in headers, false);
});

test('deferred delivery binds the immutable database response hash to the pay receipt, not the retrieve body', () => {
  const paymentReceipt = {
    operationId: '096187dd-e30b-4eeb-9d77-38e94fd49bc6',
    deliveryHandle: '096187dd-e30b-4eeb-9d77-38e94fd49bc6',
    status: 'payment_confirmed',
    payment: {
      amount: '125000', asset: `0x${'1'.repeat(40)}`, network: 'eip155:8453',
      payTo: `0x${'2'.repeat(40)}`, receiptStatus: 'success', transactionHash: `0x${'3'.repeat(64)}`,
    },
  };
  const retrievedBody = {
    operationId: paymentReceipt.operationId,
    resourceId: 'bef-market-state-brief-v1',
    contentHash: 'a'.repeat(64),
    contentBytes: Buffer.from('{"routeCode":"R1"}').toString('base64'),
  };
  const immutableReceiptHash = createHash('sha256').update(JSON.stringify(paymentReceipt)).digest('hex');
  assert.equal(deferredPaymentReceiptHashMatches(immutableReceiptHash, paymentReceipt), true);
  assert.equal(deferredPaymentReceiptHashMatches(immutableReceiptHash, retrievedBody), false);
});
