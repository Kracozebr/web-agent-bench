import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { OwnerDatabase } from "./db.js";
import { disableBonusCode, issueBonusCode, listBonusCodes, readOwnerBonusCodeRedemptions, redeemBonusCode } from "./bonus-code-service.js";
import { HttpError } from "./http-error.js";

export interface BonusCodeOwnerContext {
  owner: { id: string };
}

export interface BonusCodeAdminContext {
  context: BonusCodeOwnerContext;
}

export interface BonusCodeRouteDependencies {
  db: OwnerDatabase;
  codeVerifierSecret?: string;
  resolveOwner(request: FastifyRequest): Promise<BonusCodeOwnerContext>;
  requireAdmin(request: FastifyRequest): Promise<BonusCodeAdminContext>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
  requireOrigin(request: FastifyRequest): Promise<void>;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function requireOnlyKeys(value: unknown, allowed: string[]): Record<string, unknown> {
  const body = asRecord(value);
  if (Object.keys(body).some((key) => !allowed.includes(key))) {
    throw new HttpError(400, "INVALID_REQUEST", "The request contains unsupported fields");
  }
  return body;
}

function sendError(reply: FastifyReply, error: unknown) {
  if (error instanceof HttpError) {
    return reply.code(error.status).header("Cache-Control", "no-store").send({ error: { code: error.code, message: error.message } });
  }
  return reply.code(500).header("Cache-Control", "no-store").send({
    error: { code: "INTERNAL_ERROR", message: "The request could not be completed" }
  });
}

function ensureVerifierConfigured(secret: string | undefined): string {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) {
    throw new HttpError(503, "BONUS_CODES_UNAVAILABLE", "Bonus codes are not configured on this service");
  }
  return secret;
}

export function registerBonusCodeRoutes(app: FastifyInstance, dependencies: BonusCodeRouteDependencies): void {
  app.get("/api/admin/bonus-codes", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-admin", dependencies.rateLimitMax);
      await dependencies.requireAdmin(request);
      return reply.header("Cache-Control", "no-store").send(await listBonusCodes(dependencies.db));
    } catch (error) {
      return sendError(reply, error);
    }
  });

  app.post("/api/admin/bonus-codes", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-admin", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const admin = await dependencies.requireAdmin(request);
      const body = requireOnlyKeys(request.body, ["operationId", "label", "kind", "amount", "maximumUses"]);
      const result = await issueBonusCode(dependencies.db, {
        issuerOwnerId: admin.context.owner.id,
        codeVerifierSecret: ensureVerifierConfigured(dependencies.codeVerifierSecret),
        operationId: typeof body.operationId === "string" ? body.operationId : "",
        label: typeof body.label === "string" ? body.label : "",
        kind: body.kind as "group" | "single_use",
        amount: typeof body.amount === "string" ? body.amount : "",
        maximumUses: body.maximumUses as number
      });
      return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "no-store").send(result);
    } catch (error) {
      return sendError(reply, error);
    }
  });

  const disable = async (request: FastifyRequest<{ Params: { codeId: string } }>, reply: FastifyReply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-admin", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const admin = await dependencies.requireAdmin(request);
      const body = requireOnlyKeys(request.body, ["operationId"]);
      const result = await disableBonusCode(dependencies.db, {
        actorOwnerId: admin.context.owner.id,
        codeId: request.params.codeId,
        operationId: typeof body.operationId === "string" ? body.operationId : ""
      });
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) {
      return sendError(reply, error);
    }
  };
  app.post<{ Params: { codeId: string } }>("/api/admin/bonus-codes/:codeId/disable", disable);

  const rejectTermsEdit = async (_request: FastifyRequest<{ Params: { codeId: string } }>, reply: FastifyReply) => {
    return sendError(reply, new HttpError(409, "BONUS_CODE_TERMS_IMMUTABLE", "Bonus code terms cannot be changed; issue a replacement code"));
  };
  app.put<{ Params: { codeId: string } }>("/api/admin/bonus-codes/:codeId", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-admin", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      await dependencies.requireAdmin(request);
      return rejectTermsEdit(request, reply);
    } catch (error) {
      return sendError(reply, error);
    }
  });
  app.patch<{ Params: { codeId: string } }>("/api/admin/bonus-codes/:codeId", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-admin", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      await dependencies.requireAdmin(request);
      return rejectTermsEdit(request, reply);
    } catch (error) {
      return sendError(reply, error);
    }
  });

  app.get("/api/owner/bonus-codes/redemptions", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-owner", dependencies.rateLimitMax);
      const owner = await dependencies.resolveOwner(request);
      return reply.header("Cache-Control", "no-store").send(await readOwnerBonusCodeRedemptions(dependencies.db, owner.owner.id));
    } catch (error) {
      return sendError(reply, error);
    }
  });

  app.post("/api/owner/bonus-codes/redeem", async (request, reply) => {
    try {
      await dependencies.rateLimit(request, "bonus-code-owner", dependencies.rateLimitMax);
      await dependencies.requireOrigin(request);
      const owner = await dependencies.resolveOwner(request);
      const body = requireOnlyKeys(request.body, ["operationId", "code"]);
      const result = await redeemBonusCode(dependencies.db, {
        ownerId: owner.owner.id,
        codeVerifierSecret: ensureVerifierConfigured(dependencies.codeVerifierSecret),
        plaintextCode: typeof body.code === "string" ? body.code : "",
        operationId: typeof body.operationId === "string" ? body.operationId : ""
      });
      return reply.header("Cache-Control", "no-store").send(result);
    } catch (error) {
      return sendError(reply, error);
    }
  });
}
