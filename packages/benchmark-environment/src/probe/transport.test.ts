import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { EvidenceWriter } from './evidence.js';
import { HttpEvidenceTransport } from './transport.js';

const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

async function capturePaymentPayloadObservation(authorization: unknown): Promise<{
  observation: Record<string, unknown>;
  encoded: string;
  signature: string;
}> {
  const signature = 'secret-payment-signature-value';
  const encoded = Buffer.from(JSON.stringify({
    x402Version: 2,
    accepted: {
      scheme: 'exact', network: 'eip155:8453',
      asset: '0x3333333333333333333333333333333333333333',
      amount: '3000000', payTo: '0x2222222222222222222222222222222222222222',
    },
    payload: {
      authorization,
      signature,
    },
  })).toString('base64');
  const observations: Record<string, unknown>[] = [];
  const evidence = {
    writeObservation: async (_path: string, _id: string, body: Record<string, unknown>) => {
      observations.push(body);
      return _path;
    },
  } as unknown as EvidenceWriter;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{"accepted":true}', {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  try {
    const transport = new HttpEvidenceTransport(evidence, []);
    await transport.request({
      boundary: 'actual-tool-http', observationId: 'signed-purchase', method: 'POST',
      url: 'http://127.0.0.1/tools/test/purchase',
      headers: { 'payment-signature': encoded }, body: { resourceId: 'resource', offerId: 'canonical' },
      operationId: '00000000-0000-4000-8000-000000000001', variantId: 'canonical',
    });
  } finally {
    globalThis.fetch = originalFetch;
  }

  const observation = observations[0];
  assert.ok(observation);
  return { observation, encoded, signature };
}

test('payment payload evidence retains a validated payer and only signature digests', async () => {
  const { observation, encoded, signature } = await capturePaymentPayloadObservation({
    from: '0x1111111111111111111111111111111111111111',
    to: '0x2222222222222222222222222222222222222222',
    value: '3000000', validAfter: '0', validBefore: '1893456000', nonce: '1',
  });
  const request = observation.request as Record<string, unknown>;
  const headers = request.headers as Record<string, unknown>;
  const decoded = request.decodedPaymentPayload as Record<string, unknown>;
  assert.equal(decoded.sourceHeaderSha256, sha256(encoded));
  assert.equal(headers['payment-signature-sha256'], sha256(encoded));
  assert.equal(decoded.payloadSignatureSha256, sha256(signature));
  assert.equal(decoded.payerAddress, '0x1111111111111111111111111111111111111111');
  for (const forbidden of ['authorization', 'signature', 'nonce', 'validAfter', 'validBefore']) {
    assert.equal(Object.hasOwn(decoded, forbidden), false, `decoded metadata must omit ${forbidden}`);
  }
  assert.equal(headers['payment-signature'], '[REDACTED]');
  const serialized = JSON.stringify(observation);
  assert.equal(serialized.includes(signature), false);
  for (const forbidden of ['"authorization"', '"nonce"', '"validAfter"', '"validBefore"', '1893456000']) {
    assert.equal(serialized.includes(forbidden), false, `stored observation must omit ${forbidden}`);
  }
});

test('payment payload evidence omits a missing or malformed payer address', async () => {
  for (const authorization of [
    { to: '0x2222222222222222222222222222222222222222', value: '3000000', nonce: 'secret-nonce' },
    { from: '0x1111', to: '0x2222222222222222222222222222222222222222', value: '3000000', nonce: 'secret-nonce' },
  ]) {
    const { observation, signature } = await capturePaymentPayloadObservation(authorization);
    const request = observation.request as Record<string, unknown>;
    const decoded = request.decodedPaymentPayload as Record<string, unknown>;
    assert.equal(Object.hasOwn(decoded, 'payerAddress'), false);
    assert.equal(Object.hasOwn(decoded, 'authorization'), false);
    assert.equal(Object.hasOwn(decoded, 'nonce'), false);
    assert.equal(JSON.stringify(observation).includes(signature), false);
    assert.equal(JSON.stringify(observation).includes('secret-nonce'), false);
  }
});

test('private admin setup timeout is deadline-clamped and failure evidence is safe without retrying', async () => {
  const observations: Record<string, unknown>[] = [];
  const paths: string[] = [];
  const evidence = {
    writeObservation: async (path: string, _id: string, body: Record<string, unknown>) => {
      paths.push(path);
      observations.push(body);
      return path;
    },
  } as unknown as EvidenceWriter;
  const transport = new HttpEvidenceTransport(evidence, [], 10_000, 30_000);
  transport.setDeadlineAt(Date.now() + 100);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async (_input, init) => {
    fetchCalls += 1;
    return await new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal as AbortSignal;
      const rejectWithTimeoutError = () => {
        const error = new Error('private-key-wire-value secret-admin-key secret-url-query');
        error.name = 'TimeoutError';
        reject(error);
      };
      if (signal.aborted) rejectWithTimeoutError();
      else signal.addEventListener('abort', rejectWithTimeoutError, { once: true });
    });
  };
  try {
    await assert.rejects(transport.request({
      boundary: 'private-admin-http',
      observationId: 'slow-reset',
      method: 'POST',
      url: 'http://127.0.0.1/internal/admin/environments/bef-env-a/reset?token=secret-url-query',
      headers: { 'X-BEF-Admin-Key': 'secret-admin-key' },
      body: { payerPrivateKey: 'private-key-wire-value' },
      operationId: null,
      variantId: null,
    }), { message: 'probe_http_unavailable' });
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(fetchCalls, 1, 'the mutating setup request must not be retried');
  assert.equal(paths.length, 1);
  assert.match(paths[0]!, /-slow-reset-transport-failure\.json$/);
  const observation = observations[0]!;
  assert.equal(observation.boundary, 'private-admin-http');
  assert.equal(observation.operationId, null);
  assert.equal(observation.variantId, null);
  const request = observation.request as Record<string, unknown>;
  assert.equal(request.method, 'POST');
  assert.equal(request.path, '/internal/admin/environments/bef-env-a/reset');
  assert.equal(Object.hasOwn(request, 'headers'), false);
  assert.equal(Object.hasOwn(request, 'body'), false);
  assert.equal(Object.hasOwn(observation, 'response'), false);
  const transportObservation = observation.transport as Record<string, unknown>;
  assert.equal(transportObservation.transportError, 'TimeoutError');
  assert.ok(Number(transportObservation.effectiveTimeoutMs) > 0);
  assert.ok(Number(transportObservation.effectiveTimeoutMs) <= 100);
  assert.ok(Number(transportObservation.monotonicElapsedMs) >= 0);
  const serialized = JSON.stringify(observation);
  for (const secret of ['private-key-wire-value', 'secret-admin-key', 'secret-url-query', 'message']) {
    assert.equal(serialized.includes(secret), false, `failure evidence must omit ${secret}`);
  }
});

test('only exact private-admin reset and generation POSTs use the manifest-bounded setup timeout', async () => {
  const observations: Record<string, unknown>[] = [];
  const evidence = {
    writeObservation: async (_path: string, _id: string, body: Record<string, unknown>) => {
      observations.push(body);
      return _path;
    },
  } as unknown as EvidenceWriter;
  const transport = new HttpEvidenceTransport(evidence, [], 10_000, 250);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new TypeError('safe classification only');
  };
  const request = (boundary: 'actual-tool-http' | 'private-admin-http' | 'facilitator-http', method: string, path: string) => transport.request({
    boundary,
    observationId: 'timeout-policy',
    method,
    url: `http://127.0.0.1${path}`,
    operationId: null,
    variantId: null,
  });
  try {
    for (const [boundary, method, path] of [
      ['private-admin-http', 'POST', '/internal/admin/environments/bef-env-a/reset'],
      ['private-admin-http', 'POST', '/internal/admin/environments/bef-env-a/generations'],
      ['private-admin-http', 'GET', '/internal/admin/environments/bef-env-a/reset'],
      ['private-admin-http', 'POST', '/internal/admin/environments/bef-env-a/fence'],
      ['actual-tool-http', 'POST', '/internal/admin/environments/bef-env-a/reset'],
      ['facilitator-http', 'POST', '/internal/admin/environments/bef-env-a/reset'],
    ] as const) {
      await assert.rejects(request(boundary, method, path), { message: 'probe_http_unavailable' });
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(fetchCalls, 6, 'each failed request should be sent once');
  assert.equal(observations.length, 6);
  const effectiveTimeouts = observations.map((observation) =>
    Number((observation.transport as Record<string, unknown>).effectiveTimeoutMs));
  assert.equal(effectiveTimeouts[0], 250);
  assert.equal(effectiveTimeouts[1], 250);
  assert.equal(effectiveTimeouts[2], 10_000);
  assert.equal(effectiveTimeouts[3], 10_000);
  assert.equal(effectiveTimeouts[4], 10_000);
  assert.equal(effectiveTimeouts[5], 10_000);
});
