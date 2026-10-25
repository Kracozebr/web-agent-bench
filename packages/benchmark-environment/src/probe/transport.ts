import { createHash } from 'node:crypto';
import type { EvidenceWriter } from './evidence.js';
import { sanitizeHeaders, sanitizeValue } from './evidence.js';
import { probeFetch, type ProbeHeaders } from './fetch-types.js';

export type HttpBoundary = 'actual-tool-http' | 'private-admin-http' | 'facilitator-http';

export type CapturedHttpResponse = {
  status: number;
  headers: ProbeHeaders;
  body: unknown;
  bodyText: string;
  rawBody: Buffer;
  operationId: string | null;
};

function jsonOrText(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { text };
  }
}

function recordOf(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safePublicRequirement(value: unknown): Record<string, unknown> | undefined {
  const source = recordOf(value);
  if (!source) return undefined;
  const result: Record<string, unknown> = {};
  for (const key of ['scheme', 'network', 'asset', 'amount', 'payTo'] as const) {
    const child = source[key];
    if (typeof child !== 'string' || child.length === 0 || child.length > 256) return undefined;
    result[key] = child;
  }
  const maxTimeoutSeconds = source.maxTimeoutSeconds;
  if (typeof maxTimeoutSeconds === 'number' && Number.isSafeInteger(maxTimeoutSeconds) && maxTimeoutSeconds > 0) {
    result.maxTimeoutSeconds = maxTimeoutSeconds;
  }
  const extra = recordOf(source.extra);
  if (extra) {
    const safeExtra: Record<string, string> = {};
    for (const key of ['name', 'version', 'paymentFlow', 'assetTransferMethod'] as const) {
      const child = extra[key];
      if (typeof child === 'string' && child.length > 0 && child.length <= 256) safeExtra[key] = child;
    }
    if (Object.keys(safeExtra).length > 0) result.extra = safeExtra;
  }
  return result;
}

function decodedPaymentPayloadMetadata(headers: Record<string, string>): Record<string, unknown> | undefined {
  const entry = Object.entries(headers).find(([name]) =>
    ['payment-signature', 'x-payment-signature'].includes(name.toLowerCase()));
  if (!entry) return undefined;
  const encoded = entry[1];
  if (encoded.length === 0 || encoded.length > 65_536 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return undefined;
  let parsed: unknown;
  try {
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) return undefined;
    parsed = JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
  const source = recordOf(parsed);
  const accepted = safePublicRequirement(source?.accepted);
  if (!source || !accepted) return undefined;
  const payload = recordOf(source.payload);
  const authorization = recordOf(payload?.authorization);
  const payerAddress = typeof authorization?.from === 'string' && /^0x[0-9a-f]{40}$/i.test(authorization.from)
    ? authorization.from.toLowerCase()
    : undefined;
  const signature = typeof payload?.signature === 'string'
    ? payload.signature
    : typeof source.signature === 'string' ? source.signature : undefined;
  const result: Record<string, unknown> = {
    accepted,
    sourceHeaderSha256: createHash('sha256').update(encoded).digest('hex'),
    ...(payerAddress ? { payerAddress } : {}),
  };
  if (signature) {
    result.payloadSignatureSha256 = createHash('sha256').update(signature, 'utf8').digest('hex');
  }
  if (typeof source.x402Version === 'number' && Number.isSafeInteger(source.x402Version)) {
    result.x402Version = source.x402Version;
  }
  // Deliberately omit payload.signature, authorization, resource URL, and any
  // extension keys. The validated public payer address is the sole authorization
  // field retained; correlation uses only SHA-256 digests and the header hash.
  return result;
}

function safeDecodedPaymentRequired(
  decodedResponse: Record<string, unknown> | undefined,
  body: unknown,
  requestSecretWasEchoed: boolean,
): Record<string, unknown> | undefined {
  const declaration = recordOf(decodedResponse?.paymentRequired);
  const accepts = declaration?.accepts;
  if (!Array.isArray(accepts)) return undefined;
  const safeAccepts = accepts.map(safePublicRequirement).filter(
    (value): value is Record<string, unknown> => value !== undefined,
  );
  if (safeAccepts.length === 0) return undefined;
  const result: Record<string, unknown> = { accepts: safeAccepts };
  if (typeof declaration?.x402Version === 'number' && Number.isSafeInteger(declaration.x402Version)) {
    result.x402Version = declaration.x402Version;
  }
  // Prefer the SDK-decoded PAYMENT-REQUIRED declaration. Some servers carry
  // the protocol error only in that header while returning an empty JSON body.
  const error = declaration?.error ?? recordOf(body)?.error;
  if (!requestSecretWasEchoed && typeof error === 'string' && error.length > 0 && error.length <= 256) {
    result.error = error;
  }
  return result;
}

function safeHeaders(input: Record<string, string>, secrets: readonly string[]): Record<string, string | boolean> {
  const safe: Record<string, string | boolean> = sanitizeHeaders(input, secrets);
  for (const [name, value] of Object.entries(input)) {
    const normalized = name.toLowerCase();
    if (['authorization', 'proxy-authorization', 'payment-signature', 'x-payment-signature', 'x-bef-admin-key', 'x-bef-service-key'].includes(normalized)) {
      safe[`${name}-present`] = value.length > 0;
      if (normalized === 'authorization') {
        safe[`${name}-sha256`] = createHash('sha256').update(value).digest('hex');
      }
      if (normalized === 'payment-signature' || normalized === 'x-payment-signature') {
        safe[`${name}-sha256`] = createHash('sha256').update(value).digest('hex');
      }
    }
  }
  return safe;
}

function pathOnly(rawUrl: string): string {
  const url = new URL(rawUrl);
  return `${url.pathname}${url.search}`;
}

function failurePathOnly(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname || '/';
  } catch {
    return '[invalid-url]';
  }
}

function safeTransportErrorName(error: unknown): 'AbortError' | 'TimeoutError' | 'TypeError' | 'OtherError' {
  if (!(error instanceof Error)) return 'OtherError';
  switch (error.name) {
    case 'AbortError': return 'AbortError';
    case 'TimeoutError': return 'TimeoutError';
    case 'TypeError': return 'TypeError';
    default: return 'OtherError';
  }
}

function isPrivateAdminSetupRequest(boundary: HttpBoundary, method: string, rawUrl: string): boolean {
  if (boundary !== 'private-admin-http' || method.toUpperCase() !== 'POST') return false;
  try {
    return /^\/internal\/admin\/environments\/[^/]+\/(?:reset|generations)$/.test(new URL(rawUrl).pathname);
  } catch {
    return false;
  }
}

function responseContainsRequestSecret(rawBody: Buffer, requestHeaders: Record<string, string>, configuredSecrets: readonly string[]): boolean {
  const text = rawBody.toString('utf8');
  if (configuredSecrets.some((secret) => secret.length > 0 && text.includes(secret))) return true;
  const sensitiveHeaderNames = new Set([
    'authorization', 'proxy-authorization', 'payment-signature', 'x-payment-signature',
    'x-bef-admin-key', 'x-bef-service-key',
  ]);
  return Object.entries(requestHeaders).some(([name, value]) =>
    sensitiveHeaderNames.has(name.toLowerCase()) && value.length > 0 && text.includes(value));
}

export class HttpEvidenceTransport {
  private sequence = 0;
  private deadlineAtMs = Number.POSITIVE_INFINITY;

  constructor(
    private readonly evidence: EvidenceWriter,
    private readonly secretValues: readonly string[],
    private readonly timeoutMs = 10_000,
    private readonly privateAdminSetupTimeoutMs = timeoutMs,
  ) {}

  setDeadlineAt(deadlineAtMs: number): void {
    this.deadlineAtMs = deadlineAtMs;
  }

  async request(input: {
    boundary: HttpBoundary;
    observationId: string;
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: unknown;
    operationId: string | null;
    resolveOperationId?: (status: number, body: unknown) => Promise<string | null>;
    variantId: string | null;
    includeRawResponseBytes?: boolean;
    decodeResponse?: (status: number, headers: ProbeHeaders, body: unknown) => Record<string, unknown> | undefined;
  }): Promise<CapturedHttpResponse> {
    const headers = input.headers ?? {};
    const requestBody = input.body === undefined ? undefined : JSON.stringify(input.body);
    const remainingMs = Math.floor(this.deadlineAtMs - Date.now());
    if (remainingMs <= 0) throw new Error('probe_trial_guardrail_deadline_exceeded');
    const configuredTimeoutMs = isPrivateAdminSetupRequest(input.boundary, input.method, input.url)
      ? this.privateAdminSetupTimeoutMs
      : this.timeoutMs;
    const timeoutMs = Math.min(configuredTimeoutMs, remainingMs);
    const requestStartedMonotonicMs = performance.now();
    let response;
    try {
      response = await probeFetch(input.url, {
        method: input.method,
        headers,
        ...(requestBody === undefined ? {} : { body: requestBody }),
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      this.sequence += 1;
      const fileName = `${String(this.sequence).padStart(4, '0')}-${input.observationId}-transport-failure.json`;
      try {
        await this.evidence.writeObservation(`http/${fileName}`, `${input.observationId}-transport-failure`, {
          schemaVersion: 'bef-http-failure-observation/v1',
          boundary: input.boundary,
          operationId: input.operationId,
          variantId: input.variantId,
          request: {
            method: input.method.toUpperCase(),
            path: failurePathOnly(input.url),
            monotonicStartMs: requestStartedMonotonicMs,
          },
          transport: {
            transportError: safeTransportErrorName(error),
            effectiveTimeoutMs: timeoutMs,
            monotonicElapsedMs: Math.max(0, performance.now() - requestStartedMonotonicMs),
          },
        });
      } catch {
        // Failure evidence is best-effort and must not replace the stable probe error code.
      }
      throw new Error('probe_http_unavailable');
    }

    let rawBody: Buffer;
    try {
      rawBody = Buffer.from(await response.arrayBuffer());
    } catch {
      throw new Error('probe_http_response_unreadable');
    }
    const responseObservedMonotonicMs = performance.now();
    if (rawBody.byteLength > 1_048_576) {
      throw new Error('probe_http_response_too_large');
    }
    const bodyText = rawBody.toString('utf8');
    const containsSecret = responseContainsRequestSecret(rawBody, headers, this.secretValues);
    if (input.includeRawResponseBytes && response.ok && containsSecret) {
      throw new Error('probe_http_raw_response_contains_secret');
    }

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, name) => { responseHeaders[name] = value; });
    const parsedBody = jsonOrText(bodyText);
    const operationId = input.resolveOperationId
      ? await input.resolveOperationId(response.status, parsedBody)
      : input.operationId;
    const requestBodyForEvidence = input.body === undefined
      ? null
      : sanitizeValue(input.body, this.secretValues);
    const responseBodyForEvidence = sanitizeValue(parsedBody, this.secretValues);
    const safeResponseHeaders = safeHeaders(responseHeaders, this.secretValues);
    const decodedPayloadMetadata = decodedPaymentPayloadMetadata(headers);
    let decodedResponse: Record<string, unknown> | undefined;
    try {
      decodedResponse = input.decodeResponse?.(response.status, response.headers, parsedBody);
    } catch {
      decodedResponse = { protocolDecodeError: 'unavailable' };
    }
    const decodedPaymentRequired = safeDecodedPaymentRequired(decodedResponse, parsedBody, containsSecret);

    this.sequence += 1;
    const fileName = `${String(this.sequence).padStart(4, '0')}-${input.observationId}.json`;
    await this.evidence.writeObservation(`http/${fileName}`, input.observationId, {
      schemaVersion: 'bef-http-observation/v1',
      boundary: input.boundary,
      operationId,
      variantId: input.variantId,
      request: {
        method: input.method.toUpperCase(),
        path: pathOnly(input.url),
        monotonicStartMs: requestStartedMonotonicMs,
        headers: safeHeaders(headers, this.secretValues),
        body: requestBodyForEvidence,
        ...(decodedPayloadMetadata ? { decodedPaymentPayload: decodedPayloadMetadata } : {}),
      },
      response: {
        status: response.status,
        monotonicObservedMs: responseObservedMonotonicMs,
        headers: safeResponseHeaders,
        body: responseBodyForEvidence,
        ...(input.includeRawResponseBytes && response.ok && !containsSecret ? { bodyBase64: rawBody.toString('base64') } : {}),
        ...(decodedResponse ? { decodedProtocol: sanitizeValue(decodedResponse, this.secretValues) } : {}),
        ...(decodedPaymentRequired ? { decodedPaymentRequired } : {}),
      },
    });

    return { status: response.status, headers: response.headers, body: parsedBody, bodyText, rawBody, operationId };
  }
}
