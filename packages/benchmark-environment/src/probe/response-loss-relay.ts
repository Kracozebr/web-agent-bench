import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export type ResponseLossRelayEvent = {
  schemaVersion: 'bef-sc006-response-loss-relay/v1';
  operationId: string;
  variantId: 'response_loss';
  method: 'POST';
  path: string;
  idempotencyKeySha256: string;
  paymentSignatureSha256: string | null;
  requestBodySha256: string;
  upstreamMonotonicStartMs: number;
  upstreamMonotonicObservedMs: number;
  deliveredOperationId: string;
  deliveredResourceId: string;
  deliveredContentSha256: string;
  deliveredContentBytes: number;
  upstreamStatus: 200;
  upstreamBodySha256: string;
  downstreamClosedWithoutResponse: true;
};

export type ResponseLossRelay = {
  url: string;
  event(): ResponseLossRelayEvent | null;
  close(): Promise<void>;
};

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const part of request) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
    size += chunk.byteLength;
    if (size > 1_048_576) throw new Error('relay_request_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

function header(request: IncomingMessage, name: string): string | null {
  const value = request.headers[name.toLowerCase()];
  if (typeof value === 'string') return value;
  return Array.isArray(value) ? value.join(', ') : null;
}

function forwardedHeaders(request: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  const omitted = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'expect']);
  for (const [name, value] of Object.entries(request.headers)) {
    if (omitted.has(name.toLowerCase()) || value === undefined) continue;
    headers[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return headers;
}

export async function startResponseLossRelay(input: {
  apiBaseUrl: string;
  envId: string;
  operationId: string;
  idempotencyKey: string;
  resourceId: string;
  contentSha256: string;
}): Promise<ResponseLossRelay> {
  const target = new URL(input.apiBaseUrl);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
    throw new Error('probe_sc006_relay_target_invalid');
  }
  const expectedPath = `/tools/${encodeURIComponent(input.envId)}/purchase`;
  let captured: ResponseLossRelayEvent | null = null;
  let consumed = false;

  const server: Server = createServer((downstream, client) => {
    void (async () => {
      if (consumed || downstream.method !== 'POST' || downstream.url !== expectedPath
        || header(downstream, 'idempotency-key') !== input.idempotencyKey) {
        client.writeHead(409, { 'content-type': 'application/json' });
        client.end('{"error":"relay_request_out_of_scope"}');
        return;
      }
      consumed = true;
      const body = await readBody(downstream);
      const signature = header(downstream, 'payment-signature') ?? header(downstream, 'x-payment-signature');
      const upstreamMonotonicStartMs = performance.now();
      const upstream = await fetch(new URL(downstream.url!, target), {
        method: 'POST',
        headers: forwardedHeaders(downstream),
        ...(body.byteLength ? {
          body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
        } : {}),
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      });
      const upstreamBody = Buffer.from(await upstream.arrayBuffer());
      const upstreamMonotonicObservedMs = performance.now();
      if (upstream.status !== 200) {
        client.writeHead(502, { 'content-type': 'application/json' });
        client.end('{"error":"relay_upstream_not_successful"}');
        return;
      }
      let delivered: Record<string, unknown>;
      let deliveredBytes: Buffer;
      try {
        const parsed: unknown = JSON.parse(upstreamBody.toString('utf8'));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('response_not_object');
        delivered = parsed as Record<string, unknown>;
        if (typeof delivered.contentBytes !== 'string') throw new Error('response_content_missing');
        deliveredBytes = Buffer.from(delivered.contentBytes, 'base64');
        if (deliveredBytes.toString('base64').replace(/=+$/, '') !== delivered.contentBytes.replace(/=+$/, '')) {
          throw new Error('response_content_encoding_invalid');
        }
      } catch {
        client.writeHead(502, { 'content-type': 'application/json' });
        client.end('{"error":"relay_upstream_body_invalid"}');
        return;
      }
      const deliveredContentSha256 = sha256(deliveredBytes);
      if (delivered.operationId !== input.operationId || delivered.resourceId !== input.resourceId
        || delivered.contentHash !== input.contentSha256
        || deliveredContentSha256 !== input.contentSha256.replace(/^0x/i, '').toLowerCase()) {
        client.writeHead(502, { 'content-type': 'application/json' });
        client.end('{"error":"relay_upstream_delivery_identity_mismatch"}');
        return;
      }
      captured = {
        schemaVersion: 'bef-sc006-response-loss-relay/v1',
        operationId: input.operationId,
        variantId: 'response_loss',
        method: 'POST',
        path: expectedPath,
        idempotencyKeySha256: sha256(Buffer.from(input.idempotencyKey, 'utf8')),
        paymentSignatureSha256: signature ? sha256(Buffer.from(signature, 'utf8')) : null,
        requestBodySha256: sha256(body),
        upstreamMonotonicStartMs,
        upstreamMonotonicObservedMs,
        deliveredOperationId: String(delivered.operationId),
        deliveredResourceId: String(delivered.resourceId),
        deliveredContentSha256,
        deliveredContentBytes: deliveredBytes.byteLength,
        upstreamStatus: 200,
        upstreamBodySha256: sha256(upstreamBody),
        downstreamClosedWithoutResponse: true,
      };
      client.destroy();
    })().catch(() => {
      if (!client.destroyed) {
        client.writeHead(502, { 'content-type': 'application/json' });
        client.end('{"error":"relay_upstream_unavailable"}');
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    event: () => captured,
    close: async () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
