import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalJson } from './manifest.js';
import { buildSafeRequest } from './facilitator-observation.js';
import { sanitizeValue } from './probe/evidence.js';

const payer = '0x1111111111111111111111111111111111111111';
const payTo = '0x2222222222222222222222222222222222222222';
const asset = '0x3333333333333333333333333333333333333333';
const rawInnerSignature = `0x${'a'.repeat(130)}`;
const privateNonce = `0x${'b'.repeat(64)}`;

function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function keysOf(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(keysOf);
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [key, ...keysOf(child)]);
  }
  return [];
}

test('facilitator safe request remains hash-stable through evidence sanitization and omits signing fields', () => {
  const body = {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      resource: { url: 'http://127.0.0.1/resource', description: 'pinned resource' },
      accepted: { scheme: 'exact', network: 'eip155:8453', asset, amount: '100000', payTo },
      payload: {
        authorization: {
          from: payer,
          to: payTo,
          value: '100000',
          validAfter: '0',
          validBefore: '1893456000',
          nonce: privateNonce,
        },
        signature: rawInnerSignature,
      },
    },
    paymentRequirements: {
      scheme: 'exact', network: 'eip155:8453', asset, amount: '100000', payTo,
      maxTimeoutSeconds: 60, extra: { paymentFlow: 'authorization' },
    },
  };

  const request = buildSafeRequest(body, 'c'.repeat(64));
  const sanitized = sanitizeValue(request);
  assert.deepEqual(sanitized, request);

  const paymentPayload = request.paymentPayload as Record<string, unknown>;
  assert.deepEqual(paymentPayload.transfer, { from: payer, to: payTo, value: '100000' });
  assert.equal(paymentPayload.proofSha256, digest(rawInnerSignature));
  assert.equal(paymentPayload.x402Version, 2);
  assert.deepEqual(paymentPayload.accepted, body.paymentPayload.accepted);
  assert.deepEqual(paymentPayload.resource, body.paymentPayload.resource);
  assert.equal(
    digest(canonicalJson(sanitized)),
    digest(canonicalJson(request)),
    'the persisted request digest must remain reproducible after the database observer sanitizer',
  );

  const serialized = JSON.stringify(request);
  assert.equal(serialized.includes(rawInnerSignature), false);
  assert.equal(serialized.includes(privateNonce), false);
  assert.equal(
    keysOf(request).some((key) => /authorization|signature|nonce|validAfter|validBefore/i.test(key)),
    false,
    'the public diagnostic object must not contain signing field names',
  );
});
