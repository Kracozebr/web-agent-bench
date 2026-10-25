import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { startResponseLossRelay } from './response-loss-relay.js';

test('response-loss relay forwards the real request and drops only a successful response', async () => {
  const authorization = 'Bearer private-run-token';
  const paymentSignature = 'encoded-payment-authorization';
  const purchaseBody = { resourceId: 'bef-resource-v1', offerId: 'canonical' };
  const body = JSON.stringify(purchaseBody);
  const resourceBytes = Buffer.from('{"resource":"pinned"}', 'utf8');
  const resourceHash = createHash('sha256').update(resourceBytes).digest('hex');
  const upstreamResponse = JSON.stringify({
    operationId: 'operation-1', resourceId: 'bef-resource-v1', contentType: 'application/json',
    contentHash: resourceHash, contentBytes: resourceBytes.toString('base64'), content: { resource: 'pinned' },
  });
  let received: { url: string | undefined; authorization: string | undefined; paymentSignature: string | undefined; body: string | undefined } = {
    url: undefined, authorization: undefined, paymentSignature: undefined, body: undefined,
  };
  const api = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      received = {
        url: request.url,
        authorization: request.headers.authorization,
        paymentSignature: request.headers['payment-signature'] as string | undefined,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(upstreamResponse);
    });
  });
  api.listen(0, '127.0.0.1');
  await once(api, 'listening');
  const address = api.address();
  assert.ok(address && typeof address !== 'string');
  const relay = await startResponseLossRelay({
    apiBaseUrl: `http://127.0.0.1:${address.port}`,
    envId: 'bef-a',
    operationId: 'operation-1',
    idempotencyKey: 'same-idempotency-key',
    resourceId: 'bef-resource-v1',
    contentSha256: resourceHash,
  });
  try {
    await assert.rejects(fetch(`${relay.url}/tools/bef-a/purchase`, {
      method: 'POST',
      headers: {
        authorization,
        'payment-signature': paymentSignature,
        'idempotency-key': 'same-idempotency-key',
        'content-type': 'application/json',
      },
      body,
    }));
    assert.deepEqual(received, {
      url: '/tools/bef-a/purchase',
      authorization,
      paymentSignature,
      body,
    });
    const event = relay.event();
    assert.ok(event);
    assert.equal(event.requestBodySha256, createHash('sha256').update(body, 'utf8').digest('hex'),
      'the relay hash binds the exact forwarded request body');
    assert.equal(event.operationId, 'operation-1');
    assert.equal(event.upstreamStatus, 200);
    assert.equal(event.deliveredOperationId, 'operation-1');
    assert.equal(event.deliveredResourceId, 'bef-resource-v1');
    assert.equal(event.deliveredContentSha256, resourceHash);
    assert.equal(event.deliveredContentBytes, resourceBytes.byteLength);
    assert.ok(event.upstreamMonotonicObservedMs > event.upstreamMonotonicStartMs);
    assert.equal(event.downstreamClosedWithoutResponse, true);
    assert.equal(event.idempotencyKeySha256.length, 64);
    assert.equal(event.paymentSignatureSha256?.length, 64);
    assert.equal(JSON.stringify(event).includes(authorization), false);
    assert.equal(JSON.stringify(event).includes(paymentSignature), false);
  } finally {
    await relay.close();
    api.close();
  }
});
