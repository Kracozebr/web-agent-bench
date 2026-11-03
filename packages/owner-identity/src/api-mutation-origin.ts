import type { FastifyRequest } from 'fastify';

/** Shared by the real server and its route integration tests. */
export async function enforceApiMutationOrigin(
  request: FastifyRequest,
  publicOrigin: string,
  requireOrigin: (request: FastifyRequest) => Promise<void>,
) {
  const pathname = new URL(request.url, publicOrigin).pathname;
  // AICODE-NOTE: Public helper protocol calls use PKCE or a scoped bearer, not
  // browser cookies. Consent/import retain CSRF protection. A supplied Origin
  // must still match; absence alone is permitted only on these exact POSTs.
  const diagnosticProtocol = request.method === 'POST' &&
    (pathname === '/api/diagnostics/oauth/token' || pathname === '/api/diagnostics/cases' ||
      /^\/api\/diagnostics\/cases\/[0-9a-f-]{36}\/batches$/i.test(pathname));
  if (diagnosticProtocol) {
    if (request.headers.origin !== undefined) await requireOrigin(request);
    return;
  }
  const agentRunAcceptance = /^\/api\/agent\/run-intents\/[0-9a-f-]{36}\/accept$/i.test(pathname);
  const agentTaskOperation = /^\/api\/agent\/runs\/[0-9a-f-]{36}\/tasks\/(?:[0-9]|1[01])\/(?:actions|finish)$/i.test(pathname);
  const agentSupportReportMutation = request.method === 'POST' &&
    /^\/api\/agent\/(?:reports|report-images\/uploads|report-images\/uploads\/[0-9a-f-]{36}\/(?:chunks|finish))$/i.test(pathname);
  if (pathname.startsWith('/api/') && request.method !== 'GET' && request.method !== 'HEAD' &&
      !pathname.startsWith('/api/auth/') && pathname !== '/api/agent/mcp' && !agentRunAcceptance &&
      !agentTaskOperation && !agentSupportReportMutation) await requireOrigin(request);
}
