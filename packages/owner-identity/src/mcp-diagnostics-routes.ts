import type { FastifyInstance, FastifyRequest } from 'fastify';
import { HttpError } from './http-error.js';
import { createDiagnosticAuthorization, getDiagnosticAuthorization, consentDiagnosticAuthorization,
  exchangeDiagnosticToken, resolveDiagnosticOAuthPrincipal, diagnosticOAuthProfile,
  type DiagnosticOAuthDependencies, type DiagnosticOAuthOwner } from './mcp-diagnostics-oauth.js';
import { registerDiagnosticCase, appendDiagnosticBatch, diagnosticReceipt, listDiagnosticCases,
  getDiagnosticCase, importDiagnosticBatch, type DiagnosticDependencies } from './mcp-diagnostics-service.js';

export interface DiagnosticRouteDependencies {
  service: DiagnosticDependencies;
  oauth: DiagnosticOAuthDependencies;
  resolveOwner(request: FastifyRequest): Promise<DiagnosticOAuthOwner>;
  requireAdmin(request: FastifyRequest): Promise<unknown>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, bucket: string, maximum: number): Promise<void>;
}

// AICODE-NOTE: The helper has a separate write-only audience; native agent
// credentials never authorize diagnostic uploads or private diagnostic reads.
export function registerDiagnosticRoutes(app: FastifyInstance, d: DiagnosticRouteDependencies) {
  const limit = (request: FastifyRequest) => d.rateLimit(request, 'diagnostics-ip', 120);
  const helper = async (request: FastifyRequest) => {
    await limit(request);
    const header = request.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer (mcd_a_[A-Za-z0-9_-]{43})$/.exec(header) : null;
    if (!match) throw new HttpError(401, 'DIAGNOSTICS_UNAUTHORIZED', 'A diagnostic helper authorization is required');
    const p = await resolveDiagnosticOAuthPrincipal(d.oauth, match[1]!);
    return {ownerId:p.ownerId,agentId:p.agentId,connectionId:p.connectionId};
  };
  app.get('/api/identity/diagnostics-profile', async (_request, reply) =>
    reply.header('Cache-Control', 'no-store').send(diagnosticOAuthProfile(d.oauth.config)));
  app.get('/api/diagnostics/oauth/authorize', async (request, reply) => {
    await limit(request);
    const result = await createDiagnosticAuthorization(d.oauth, request.query);
    return reply.header('Cache-Control', 'no-store').header('Referrer-Policy', 'no-referrer').redirect(result.consentPath);
  });
  app.get<{Params:{requestId:string}}>('/api/owner/diagnostics/oauth/requests/:requestId', async (request, reply) => {
    await limit(request);
    return reply.header('Cache-Control', 'no-store').send(await getDiagnosticAuthorization(d.oauth, await d.resolveOwner(request), request.params.requestId));
  });
  app.post('/api/diagnostics/oauth/consent', async (request, reply) => {
    await limit(request); await d.requireOrigin(request);
    return reply.header('Cache-Control', 'no-store').send(await consentDiagnosticAuthorization(d.oauth, await d.resolveOwner(request), request.body));
  });
  app.post('/api/diagnostics/oauth/token', {bodyLimit:8192}, async (request, reply) => {
    await limit(request);
    return reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache').send(await exchangeDiagnosticToken(d.oauth, request.body));
  });
  app.post('/api/diagnostics/cases', async (request, reply) =>
    reply.header('Cache-Control', 'no-store').send(await registerDiagnosticCase(d.service, await helper(request), request.body)));
  app.post<{Params:{caseId:string}}>('/api/diagnostics/cases/:caseId/batches', {bodyLimit:64*1024}, async (request, reply) =>
    reply.header('Cache-Control', 'no-store').send(await appendDiagnosticBatch(d.service, await helper(request), request.params.caseId, request.body)));
  app.get<{Params:{caseId:string};Querystring:{segmentId?:string}}>('/api/diagnostics/cases/:caseId/receipt', async (request, reply) =>
    reply.header('Cache-Control', 'no-store').send(await diagnosticReceipt(d.service, await helper(request), request.params.caseId, request.query.segmentId)));
  app.post('/api/owner/diagnostics/import', {bodyLimit:64*1024}, async (request, reply) => {
    await limit(request); await d.requireOrigin(request);
    return reply.header('Cache-Control', 'no-store').send(await importDiagnosticBatch(d.service, (await d.resolveOwner(request)).ownerId, request.body));
  });
  for (const role of ['owner', 'admin'] as const) {
    const owner = async (request:FastifyRequest) => {
      await limit(request);
      if (role === 'admin') { await d.requireAdmin(request); return null; }
      return (await d.resolveOwner(request)).ownerId;
    };
    app.get<{Querystring:{runId?:string}}>(`/api/${role}/diagnostics/cases`, async (request, reply) =>
      reply.header('Cache-Control', 'no-store').send(await listDiagnosticCases(d.service, await owner(request), request.query.runId ? {runId:request.query.runId} : {})));
    app.get<{Params:{caseId:string}}>(`/api/${role}/diagnostics/cases/:caseId`, async (request, reply) =>
      reply.header('Cache-Control', 'no-store').send(await getDiagnosticCase(d.service, await owner(request), request.params.caseId)));
  }
}
