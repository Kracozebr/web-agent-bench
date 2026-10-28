import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import { loadApplicationRuntime, type ApplicationRuntime } from './runtime.js';
import { createPaymentProtocol, type PaymentProtocol } from './protocol.js';
import { registerToolRoutes } from './tools.js';
import { registerAdminRoutes } from './admin-routes.js';
import { registerParticipantDenialAudit } from './participant-denials.js';
import { registerSelectedExecutionRoutes } from './selected-execution.js';
import { PostgresExecutionPersistence } from './selected-execution-persistence.js';

function healthDocument(runtime: ApplicationRuntime) {
  return {
    status: 'ready',
    boundary: 'benchmark-environment-api',
    manifestSha256: runtime.loadedManifest.sha256,
    applicationSourceSha256: runtime.applicationSourceSha256,
    apiNodeVersion: process.version,
    apiPackageVersion: runtime.apiPackageVersion,
    dependencyVersions: runtime.dependencyVersions,
    postgresVersion: runtime.postgresVersion,
    environments: [...runtime.envs.values()].map((environment) => ({
      envId: environment.id,
      anvil: environment.anvilIdentity,
      facilitator: {
        address: environment.facilitatorAddress,
        facilitatorNodeVersion: environment.facilitatorIdentity.facilitatorNodeVersion,
        facilitatorPackageVersion: environment.facilitatorIdentity.facilitatorPackageVersion,
        dependencyVersions: environment.facilitatorIdentity.dependencyVersions,
      },
    })),
  };
}

export async function startApi(): Promise<void> {
  const runtime = await loadApplicationRuntime();
  const protocols = new Map<string, PaymentProtocol>();
  for (const environment of runtime.envs.values()) {
    protocols.set(environment.id, await createPaymentProtocol(environment, runtime.manifest, runtime.config.serviceKey));
  }

  const app = Fastify({
    logger: false,
    disableRequestLogging: true,
    bodyLimit: runtime.manifest.guardrails.maxHttpRequestBytes,
    requestTimeout: runtime.manifest.guardrails.maxTrialSeconds * 1000,
  });
  app.get('/healthz', async () => healthDocument(runtime));
  app.setNotFoundHandler(async (_request, reply) => reply.code(404).send({ error: 'route_not_found' }));
  app.setErrorHandler(async (error, _request, reply) => {
    if (reply.sent) return;
    const code = typeof (error as { statusCode?: unknown }).statusCode === 'number'
      ? (error as { statusCode: number }).statusCode
      : 500;
    return reply.code(code >= 400 && code < 600 ? code : 500).send({ error: code >= 500 ? 'internal_request_failure' : 'invalid_request' });
  });

  const executionPersistence = new PostgresExecutionPersistence({
    manifestSha256: runtime.loadedManifest.sha256,
    feePolicy: runtime.manifest.feePolicy,
    routePools: [
      { feeTier: 500, address: runtime.manifest.contracts.pool.address, codeHash: runtime.manifest.contracts.pool.codeHash },
      ...(runtime.manifest.contracts.pool3000 ? [{
        feeTier: 3000 as const,
        address: runtime.manifest.contracts.pool3000.address,
        codeHash: runtime.manifest.contracts.pool3000.codeHash,
      }] : []),
    ],
  });

  registerParticipantDenialAudit(app, runtime);
  await registerAdminRoutes(app, runtime, executionPersistence);
  await registerToolRoutes(app, runtime, protocols);
  await registerSelectedExecutionRoutes(app, runtime, {
    signerStore: runtime.signerStore,
    persistence: executionPersistence,
    transactionRpcUrls: new Map([...runtime.envs].map(([envId, environment]) => [envId, environment.adminRpcUrl])),
  });
  await app.listen({ port: runtime.config.port, host: runtime.config.bindAddress });

  let closing = false;
  const shutdown = async () => {
    if (closing) return;
    closing = true;
    await app.close();
    runtime.signerStore.eraseAll();
    await runtime.pool.end();
  };
  process.once('SIGINT', () => { void shutdown(); });
  process.once('SIGTERM', () => { void shutdown(); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void startApi().catch(() => {
    process.stderr.write('BEF_API_STARTUP_FAILED\n');
    process.exitCode = 1;
  });
}
