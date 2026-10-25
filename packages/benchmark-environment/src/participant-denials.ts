import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ApplicationRuntime } from './runtime.js';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const routePrefix = /^\/tools\//;

function sha256(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function boundedHeader(value: string | string[] | undefined, maximum: number): string | null {
  const candidate = Array.isArray(value) ? value[0] : value;
  return typeof candidate === 'string' && candidate.length <= maximum ? candidate : null;
}

function participantRoute(request: FastifyRequest, runtime: ApplicationRuntime): { route: string; envId: string | null } | null {
  const target = request.url.split('?', 1)[0] ?? request.url;
  if (!routePrefix.test(target)) return null;
  const match = /^\/tools\/([A-Za-z0-9_-]{1,64})(?:\/.*)?$/.exec(target);
  const candidateEnvId = match?.[1] ?? null;
  const envId = candidateEnvId && runtime.envs.has(candidateEnvId) ? candidateEnvId : null;
  const endpointMatch = /^\/tools\/[A-Za-z0-9_-]{1,64}\/(offer|purchase|balances|quote|approve|wrap|unwrap|swap)$/.exec(target);
  const knownEndpoint = envId && endpointMatch?.[1] ? endpointMatch[1] : null;
  const safeEnvSegment = envId ?? '[unknown-environment]';
  return {
    route: knownEndpoint
      ? `/tools/${safeEnvSegment}/${knownEndpoint}`
      : `/tools/${safeEnvSegment}/[unknown]`,
    envId,
  };
}

function generationClaim(request: FastifyRequest): string | null {
  const value = boundedHeader(request.headers['x-bef-generation'], 64);
  return value && uuidPattern.test(value) ? value : null;
}

function requestDescriptorHash(request: FastifyRequest, route: string, runtime: ApplicationRuntime): string {
  const parsedBody = request.body;
  let bodySha256: string | null = null;
  let bodyState: 'parsed' | 'unparsed' | 'absent' = 'absent';
  if (parsedBody !== undefined) {
    try {
      const serialized = JSON.stringify(parsedBody);
      if (serialized !== undefined && Buffer.byteLength(serialized, 'utf8') <= runtime.manifest.guardrails.maxHttpRequestBytes) {
        bodySha256 = sha256(serialized);
        bodyState = 'parsed';
      } else {
        bodyState = 'unparsed';
      }
    } catch {
      bodyState = 'unparsed';
    }
  } else {
    const length = boundedHeader(request.headers['content-length'], 20);
    const transferEncoding = boundedHeader(request.headers['transfer-encoding'], 32);
    if ((length && /^[0-9]+$/.test(length) && BigInt(length) > 0n) || transferEncoding !== null) {
      bodyState = 'unparsed';
    }
  }

  const declaredLength = boundedHeader(request.headers['content-length'], 20);
  const requestTarget = request.url;
  const queryStart = requestTarget.indexOf('?');
  const query = queryStart >= 0 ? requestTarget.slice(queryStart + 1) : '';
  const descriptor = {
    method: request.method.toUpperCase(),
    route,
    generationId: generationClaim(request),
    authorizationPresent: Boolean(request.headers.authorization),
    paymentSignaturePresent: Boolean(request.headers['payment-signature'] || request.headers['x-payment']),
    contentType: boundedHeader(request.headers['content-type'], 128),
    declaredContentLength: declaredLength && /^[0-9]+$/.test(declaredLength) ? declaredLength : null,
    querySha256: query && Buffer.byteLength(query, 'utf8') <= 4096 ? sha256(query) : null,
    queryDigestUnavailable: Boolean(query) && Buffer.byteLength(query, 'utf8') > 4096,
    bodyState,
    bodySha256,
  };
  return sha256(JSON.stringify(descriptor));
}

function reasonCode(statusCode: number): string {
  if (statusCode === 401) return 'participant_authentication_denied';
  if (statusCode === 403) return 'participant_generation_scope_denied';
  if (statusCode === 404) return 'participant_route_not_found';
  if (statusCode === 413) return 'participant_request_limit_exceeded';
  if (statusCode === 400) return 'participant_request_invalid';
  return 'participant_request_denied';
}

/**
 * Persist one operationless audit row for participant requests rejected before
 * an operation exists. The hook records a bounded hash-only request descriptor;
 * credentials, signatures, and parsed request bodies are never stored here.
 */
export function registerParticipantDenialAudit(app: FastifyInstance, runtime: ApplicationRuntime): void {
  const audited = new WeakSet<FastifyRequest>();

  app.addHook('onSend', async (request, reply, payload) => {
    const routeInfo = participantRoute(request, runtime);
    const statusCode = reply.statusCode;
    if (!routeInfo || statusCode < 400 || statusCode >= 500 || statusCode === 402
      || reply.getHeader('x-bef-operation-id') !== undefined || audited.has(request)) {
      return payload;
    }

    audited.add(request);
    const denialId = randomUUID();
    const { route, envId } = routeInfo;
    const generationId = generationClaim(request);
    try {
      await runtime.pool.query(
        `INSERT INTO bef_denial(denial_id,env_id,generation_id,operation_id,route,reason_code,request_sha256)
         VALUES($1,$2,$3,NULL,$4,$5,$6)`,
        [denialId, envId, generationId, route, reasonCode(statusCode), requestDescriptorHash(request, route, runtime)],
      );
      reply.header('X-BEF-Denial-Id', denialId);
      return payload;
    } catch {
      // Replace the intended client error with a fixed response if its durable
      // denial cannot be recorded. Do not reveal database details or grant work.
      reply.code(503);
      reply.type('application/json; charset=utf-8');
      reply.removeHeader('content-length');
      return JSON.stringify({ error: 'denial_audit_unavailable' });
    }
  });
}
