import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { buildBetaUsageSupportExport, type PinnedBetaClientRegistry } from "./beta-usage-support-export.js";

type AdminOwnerContext = { context: { owner: { id: string } } };

export interface BetaUsageSupportRouteDependencies {
  db: OwnerDatabase;
  clientRegistry?: PinnedBetaClientRegistry;
  requireAdmin(request: FastifyRequest): Promise<AdminOwnerContext>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
}

function errorResponse(reply: FastifyReply, error: unknown) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header("Cache-Control", "no-store").header("Pragma", "no-cache")
      .send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").header("Pragma", "no-cache")
    .send({ error: { code: "INTERNAL_ERROR", message: "The usage/support export could not be generated" } });
}

export function registerBetaUsageSupportRoutes(app: FastifyInstance, dependencies: BetaUsageSupportRouteDependencies): void {
  app.get("/api/admin/operations/usage-support-export", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "beta-usage-support-admin", dependencies.rateLimitMax);
      await dependencies.requireAdmin(request);
      if (!dependencies.clientRegistry) {
        throw new HttpError(503, "BETA_USAGE_REGISTRY_UNAVAILABLE", "A validated Beta client registry is required for this export");
      }
      const result = await buildBetaUsageSupportExport(dependencies.db, dependencies.clientRegistry);
      return reply.header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Disposition", 'attachment; filename="beta-usage-support.json"')
        .type("application/json; charset=utf-8")
        .send(result);
    } catch (error) {
      return errorResponse(reply, error);
    }
  });
}
