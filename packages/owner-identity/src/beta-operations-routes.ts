import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { readBetaOperationsSnapshot } from './beta-operations-observability.js';
import { updateBetaOperationsControl, type BetaOperationsMode, type BetaOperationsReason } from './beta-operations-control.js';

type AdminOwnerContext = { context: { owner: { id: string } } };
export interface BetaOperationsRouteDependencies {
  db: OwnerDatabase;
  privateDataDir?: string;
  workerLease(): boolean | null;
  runtimeHealth(): Promise<'ready' | 'unavailable' | 'not_configured'>;
  environmentCapacity(): Promise<'ready' | 'unavailable' | 'not_configured'>;
  requireAdmin(request: FastifyRequest): Promise<AdminOwnerContext>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function onlyKeys(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const body = record(value);
  if (Object.keys(body).some((key) => !keys.includes(key))) {
    throw new HttpError(400, 'INVALID_OPERATIONS_CONTROL', 'The request contains unsupported fields');
  }
  return body;
}

function errorResponse(reply: FastifyReply, error: unknown) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header('Cache-Control', 'no-store').send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header('Cache-Control', 'no-store').send({
    error: { code: 'INTERNAL_ERROR', message: 'The operations request could not be completed' },
  });
}

export function registerBetaOperationsRoutes(app: FastifyInstance, dependencies: BetaOperationsRouteDependencies): void {
  app.get('/api/admin/operations', async (request, reply) => {
    try {
      await dependencies.rateLimit(request, 'beta-operations-admin', dependencies.rateLimitMax);
      await dependencies.requireAdmin(request);
      const [runtimeHealth, environmentCapacity] = await Promise.all([
        dependencies.runtimeHealth(), dependencies.environmentCapacity(),
      ]);
      const snapshot = await readBetaOperationsSnapshot({
        db: dependencies.db,
        ...(dependencies.privateDataDir ? { privateDataDir: dependencies.privateDataDir } : {}),
        workerLease: dependencies.workerLease(), betaRuntimeHealth: runtimeHealth, environmentCapacity,
      });
      return reply.header('Cache-Control', 'no-store').send(snapshot);
    } catch (error) {
      return errorResponse(reply, error);
    }
  });

  app.post('/api/admin/operations/control', async (request, reply) => {
    try {
      await dependencies.rateLimit(request, 'beta-operations-admin', dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const admin = await dependencies.requireAdmin(request);
      const body = onlyKeys(request.body, ['operationId', 'expectedRevision', 'mode', 'reasonCode']);
      if (typeof body.operationId !== 'string' || !Number.isSafeInteger(body.expectedRevision) ||
          (body.mode !== 'active' && body.mode !== 'paused') || typeof body.reasonCode !== 'string') {
        throw new HttpError(400, 'INVALID_OPERATIONS_CONTROL', 'The operations-control update is malformed');
      }
      const result = await updateBetaOperationsControl(dependencies.db, {
        actorOwnerId: admin.context.owner.id,
        operationId: body.operationId,
        expectedRevision: body.expectedRevision as number,
        mode: body.mode as BetaOperationsMode,
        reasonCode: body.reasonCode as BetaOperationsReason,
      });
      return reply.code(result.replayed ? 200 : 201).header('Cache-Control', 'no-store').send(result);
    } catch (error) {
      return errorResponse(reply, error);
    }
  });
}
