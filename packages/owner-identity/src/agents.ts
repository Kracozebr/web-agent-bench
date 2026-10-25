import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import {
  agentOperations,
  agentPolicies,
  agentProfiles,
  agentAccessGrants,
  agentManualCredentials,
  agentCancellationOutbox,
  auditEvents
} from "./schema.js";

const permissionKeys = ["training", "ranked", "forumMessages", "customTopics"] as const;
type PermissionKey = (typeof permissionKeys)[number];
type PermissionSet = Record<PermissionKey, boolean>;
type AgentProfile = typeof agentProfiles.$inferSelect;
type AgentPolicy = typeof agentPolicies.$inferSelect;
type AgentTransaction = Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0];
type AgentAccessGrant = typeof agentAccessGrants.$inferSelect;
type AgentManualCredential = typeof agentManualCredentials.$inferSelect;

const manualCredentialPrefix = "aap1_";
const minManualCredentialTtlSeconds = 300;
const maxManualCredentialTtlSeconds = 2592000;

export interface AgentCard {
  id: string;
  name: string;
  description: string;
  clientMetadata: { clientName: string | null; modelName: string | null };
  declaredVersion: string | null;
  metadataTrust: "owner-declared-unverified";
  revision: number;
  policyRevision: number;
  permissions: PermissionSet;
  createdAt: string;
  updatedAt: string;
}

export interface AgentOwnerContext {
  owner: { id: string; admissionStatus: string };
}

export interface AgentRouteDependencies {
  db: OwnerDatabase;
  resolveOwner(request: FastifyRequest): Promise<AgentOwnerContext>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
  credentialRateLimitMax: number;
  preflightRateLimitMax: number;
  manualCredentialTtlSeconds: number;
  agentResource: string;
  agentPreflightUrl: string;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new HttpError(400, "INVALID_REQUEST", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function rejectUnknownKeys(value: Record<string, unknown>, allowed: readonly string[]) {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new HttpError(400, "UNKNOWN_FIELD", "The request contains an unsupported field");
  }
}

function parseOperationId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(value)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "operationId must be a 12-128 character idempotency key");
  }
  return value;
}

function parseRevision(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new HttpError(400, "INVALID_REVISION", `${field} must be a positive integer`);
  }
  return value as number;
}

function parseManualCredentialTtl(value: unknown, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < minManualCredentialTtlSeconds ||
    (value as number) > maxManualCredentialTtlSeconds) {
    throw new HttpError(400, "INVALID_EXPIRY", `expiresInSeconds must be between ${minManualCredentialTtlSeconds} and ${maxManualCredentialTtlSeconds}`);
  }
  return value as number;
}

function parseCredentialIntent(value: unknown): "issue" | "replace" {
  if (value !== "issue" && value !== "replace") {
    throw new HttpError(400, "INVALID_CREDENTIAL_INTENT", "intent must be issue or replace");
  }
  return value;
}

function parseText(value: unknown, field: string, maxLength: number, allowEmpty = false): string {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const normalized = value.trim();
  if ((!allowEmpty && normalized.length === 0) || normalized.length > maxLength) {
    throw new HttpError(400, "INVALID_FIELD", `${field} is outside its allowed length`);
  }
  return normalized;
}

function parseOptionalNullableText(value: unknown, field: string, maxLength: number): string | null {
  if (value === null) return null;
  if (typeof value !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string or null`);
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new HttpError(400, "INVALID_FIELD", `${field} is too long`);
  return normalized.length === 0 ? null : normalized;
}

function parseCreateMetadata(value: unknown): { clientName: string | null; modelName: string | null } {
  if (value === undefined || value === null) return { clientName: null, modelName: null };
  const metadata = record(value, "clientMetadata");
  rejectUnknownKeys(metadata, ["clientName", "modelName"]);
  return {
    clientName: metadata.clientName === undefined ? null : parseOptionalNullableText(metadata.clientName, "clientMetadata.clientName", 120),
    modelName: metadata.modelName === undefined ? null : parseOptionalNullableText(metadata.modelName, "clientMetadata.modelName", 120)
  };
}

function parseMetadataPatch(value: unknown): { clientName?: string | null; modelName?: string | null } | null {
  if (value === null) return null;
  const metadata = record(value, "clientMetadata");
  rejectUnknownKeys(metadata, ["clientName", "modelName"]);
  if (Object.keys(metadata).length === 0) throw new HttpError(400, "INVALID_FIELD", "clientMetadata must update at least one supported field");
  return {
    ...(Object.hasOwn(metadata, "clientName") ? { clientName: parseOptionalNullableText(metadata.clientName, "clientMetadata.clientName", 120) } : {}),
    ...(Object.hasOwn(metadata, "modelName") ? { modelName: parseOptionalNullableText(metadata.modelName, "clientMetadata.modelName", 120) } : {})
  };
}

function parsePermissionObject(value: unknown, partial: boolean): Partial<PermissionSet> {
  const permissions = record(value, "permissions");
  rejectUnknownKeys(permissions, permissionKeys);
  if (!partial && permissionKeys.some((key) => !Object.hasOwn(permissions, key))) {
    throw new HttpError(400, "INVALID_PERMISSIONS", "All four permission booleans are required");
  }
  const result: Partial<PermissionSet> = {};
  for (const key of permissionKeys) {
    if (!Object.hasOwn(permissions, key)) continue;
    if (typeof permissions[key] !== "boolean") throw new HttpError(400, "INVALID_PERMISSIONS", `permissions.${key} must be boolean`);
    result[key] = permissions[key] as boolean;
  }
  return result;
}

function defaultPermissions(partial?: Partial<PermissionSet>): PermissionSet {
  return {
    training: partial?.training ?? false,
    ranked: partial?.ranked ?? false,
    forumMessages: partial?.forumMessages ?? false,
    customTopics: partial?.customTopics ?? false
  };
}

function normalizeMetadata(value: unknown): { clientName: string | null; modelName: string | null } {
  const metadata = record(value, "stored clientMetadata");
  return {
    clientName: typeof metadata.clientName === "string" ? metadata.clientName : null,
    modelName: typeof metadata.modelName === "string" ? metadata.modelName : null
  };
}

function toAgentCard(profile: AgentProfile, policy: AgentPolicy): AgentCard {
  return {
    id: profile.id,
    name: profile.name,
    description: profile.description,
    clientMetadata: normalizeMetadata(profile.clientMetadata),
    declaredVersion: profile.declaredVersion,
    metadataTrust: "owner-declared-unverified",
    revision: profile.revision,
    policyRevision: policy.revision,
    permissions: {
      training: policy.training,
      ranked: policy.ranked,
      forumMessages: policy.forumMessages,
      customTopics: policy.customTopics
    },
    createdAt: profile.createdAt.toISOString(),
    updatedAt: profile.updatedAt.toISOString()
  };
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(",")}}`;
}

function hashPayload(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

async function claimOperation(
  tx: AgentTransaction,
  input: { operationId: string; ownerId: string; agentId: string | null; action: string; payloadHash: string }
): Promise<AgentCard | undefined> {
  const inserted = await tx.insert(agentOperations).values({
    ...input,
    responseJson: null,
    createdAt: new Date()
  }).onConflictDoNothing({ target: agentOperations.operationId }).returning({ operationId: agentOperations.operationId });
  if (inserted.length === 1) return undefined;

  const previous = await tx.query.agentOperations.findFirst({ where: eq(agentOperations.operationId, input.operationId) });
  const agentMismatch = input.action !== "agent.create" && previous?.agentId !== input.agentId;
  if (!previous || previous.ownerId !== input.ownerId || agentMismatch ||
    previous.action !== input.action || previous.payloadHash !== input.payloadHash || !previous.responseJson) {
    throw new HttpError(409, "OPERATION_ID_CONFLICT", "operationId was already used for a different owner operation");
  }
  return previous.responseJson as AgentCard;
}

async function saveOperation(tx: AgentTransaction, operationId: string, agentId: string, card: AgentCard) {
  await tx.update(agentOperations).set({ agentId, responseJson: card }).where(eq(agentOperations.operationId, operationId));
}

type SafeReceipt = Record<string, unknown>;

async function claimSafeOperation(
  tx: AgentTransaction,
  input: { operationId: string; ownerId: string; agentId: string; action: string; payloadHash: string }
): Promise<SafeReceipt | undefined> {
  const inserted = await tx.insert(agentOperations).values({
    ...input,
    responseJson: null,
    createdAt: new Date()
  }).onConflictDoNothing({ target: agentOperations.operationId }).returning({ operationId: agentOperations.operationId });
  if (inserted.length === 1) return undefined;

  const previous = await tx.query.agentOperations.findFirst({ where: eq(agentOperations.operationId, input.operationId) });
  if (!previous || previous.ownerId !== input.ownerId || previous.agentId !== input.agentId ||
    previous.action !== input.action || previous.payloadHash !== input.payloadHash ||
    !previous.responseJson || typeof previous.responseJson !== "object" || Array.isArray(previous.responseJson)) {
    throw new HttpError(409, "OPERATION_ID_CONFLICT", "operationId was already used for a different owner operation");
  }
  const receipt = previous.responseJson as SafeReceipt;
  if (Object.hasOwn(receipt, "secret") || Object.hasOwn(receipt, "token")) {
    throw new Error("A secret-bearing agent operation receipt was found");
  }
  return receipt;
}

async function saveOperationReceipt(tx: AgentTransaction, operationId: string, agentId: string, receipt: SafeReceipt) {
  await tx.update(agentOperations).set({ agentId, responseJson: receipt }).where(eq(agentOperations.operationId, operationId));
}

function accessView(profile: AgentProfile) {
  return {
    status: profile.accessRevokedAt ? "revoked" as const : "active" as const,
    revision: profile.accessRevision,
    revokedAt: profile.accessRevokedAt?.toISOString() ?? null
  };
}

function credentialView(grant: AgentAccessGrant, credential: AgentManualCredential, now = new Date()) {
  const status = grant.revokedAt
    ? grant.revocationReason === "replaced" ? "replaced" as const : "revoked" as const
    : grant.expiresAt <= now ? "expired" as const : "active" as const;
  return {
    id: credential.id,
    grantId: grant.id,
    status,
    role: grant.role,
    resource: grant.resource,
    createdAt: grant.createdAt.toISOString(),
    expiresAt: grant.expiresAt.toISOString(),
    revokedAt: grant.revokedAt?.toISOString() ?? null,
    revocationReason: grant.revocationReason
  };
}

async function auditAccess(
  tx: AgentTransaction,
  eventType: string,
  operationId: string,
  ownerId: string,
  agentId: string,
  policyRevision: number,
  metadata: Record<string, unknown>
) {
  await tx.insert(auditEvents).values({
    id: randomUUID(), eventType, operationId,
    actorOwnerId: ownerId, subjectOwnerId: ownerId,
    invitationId: null, policyRevision,
    metadata: { agentId, ...metadata },
    createdAt: new Date()
  });
}

async function audit(
  tx: AgentTransaction,
  eventType: string,
  operationId: string,
  ownerId: string,
  agentId: string,
  card: AgentCard,
  changedFields: string[]
) {
  await tx.insert(auditEvents).values({
    id: randomUUID(), eventType, operationId,
    actorOwnerId: ownerId, subjectOwnerId: ownerId,
    invitationId: null, policyRevision: card.policyRevision,
    metadata: {
      agentId,
      revision: card.revision,
      policyRevision: card.policyRevision,
      changedFields
    },
    createdAt: new Date()
  });
}

async function admittedOwner(request: FastifyRequest, dependencies: AgentRouteDependencies): Promise<AgentOwnerContext> {
  const context = await dependencies.resolveOwner(request);
  if (context.owner.admissionStatus !== "admitted") {
    throw new HttpError(403, "FORBIDDEN", "Admission is required to manage agents");
  }
  return context;
}

async function lockOwnedProfile(tx: AgentTransaction, agentId: string, ownerId: string): Promise<AgentProfile> {
  // AICODE-NOTE: Profile and permission mutations lock the same owner-scoped
  // agent row before reading or writing, keeping partial metadata merges and
  // returned profile/policy snapshots coherent under concurrent owner tabs.
  // Idempotent mutations must claim their operation key before acquiring this
  // lock so competing actions cannot deadlock on operation-id and agent-row locks.
  const locked = await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${agentId} AND owner_id=${ownerId} FOR NO KEY UPDATE`);
  if (locked.length !== 1) throw uuidError();
  const profile = await tx.query.agentProfiles.findFirst({ where: and(
    eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, ownerId)
  ) });
  if (!profile) throw uuidError();
  return profile;
}

function validAgentId(value: string): boolean {
  return /^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(value);
}

const uuidError = () => new HttpError(404, "AGENT_NOT_FOUND", "Agent was not found");

export function registerAgentRoutes(app: FastifyInstance, dependencies: AgentRouteDependencies) {
  app.get("/api/owner/agents", async (request, reply) => {
    const context = await admittedOwner(request, dependencies);
    const rows = await dependencies.db.select({ profile: agentProfiles, policy: agentPolicies })
      .from(agentProfiles)
      .innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
      .where(eq(agentProfiles.ownerId, context.owner.id))
      .orderBy(desc(agentProfiles.updatedAt), desc(agentProfiles.createdAt));
    return reply.header("Cache-Control", "no-store").send({ agents: rows.map(({ profile, policy }) => toAgentCard(profile, policy)) });
  });

  app.get<{ Params: { agentId: string } }>("/api/owner/agents/:agentId", async (request, reply) => {
    const context = await admittedOwner(request, dependencies);
    if (!validAgentId(request.params.agentId)) throw uuidError();
    const rows = await dependencies.db.select({ profile: agentProfiles, policy: agentPolicies })
      .from(agentProfiles)
      .innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
      .where(and(eq(agentProfiles.id, request.params.agentId), eq(agentProfiles.ownerId, context.owner.id)))
      .limit(1);
    const row = rows[0];
    if (!row) throw uuidError();
    return reply.header("Cache-Control", "no-store").send({ agent: toAgentCard(row.profile, row.policy) });
  });

  app.post("/api/owner/agents", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-cards", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "name", "description", "clientMetadata", "declaredVersion", "permissions"]);
    const opId = parseOperationId(body.operationId);
    const name = parseText(body.name, "name", 80);
    const description = body.description === undefined ? "" : parseText(body.description, "description", 2000, true);
    const clientMetadata = parseCreateMetadata(body.clientMetadata);
    const declaredVersion = body.declaredVersion === undefined ? null : parseOptionalNullableText(body.declaredVersion, "declaredVersion", 80);
    const permissions = body.permissions === undefined ? defaultPermissions() : defaultPermissions(parsePermissionObject(body.permissions, true));
    const payloadHash = hashPayload({ name, description, clientMetadata, declaredVersion, permissions });
    const agentId = randomUUID();

    const result = await dependencies.db.transaction(async (tx) => {
      const replay = await claimOperation(tx, {
        operationId: opId, ownerId: context.owner.id, agentId: null,
        action: "agent.create", payloadHash
      });
      if (replay) return { card: replay, replayed: true };

      const now = new Date();
      const [profile] = await tx.insert(agentProfiles).values({
        id: agentId, ownerId: context.owner.id, name, description,
        clientMetadata, declaredVersion, revision: 1, createdAt: now, updatedAt: now
      }).returning();
      const [policy] = await tx.insert(agentPolicies).values({
        agentId,
        training: permissions.training,
        ranked: permissions.ranked,
        forumMessages: permissions.forumMessages,
        customTopics: permissions.customTopics,
        revision: 1,
        updatedAt: now
      }).returning();
      if (!profile || !policy) throw new Error("Agent creation did not return persisted rows");
      const card = toAgentCard(profile, policy);
      await saveOperation(tx, opId, agentId, card);
      await audit(tx, "agent.created", opId, context.owner.id, agentId, card, ["profile", "permissions"]);
      return { card, replayed: false };
    });
    return reply.code(result.replayed ? 200 : 201).header("Cache-Control", "no-store").send({ agent: result.card });
  });

  app.patch<{ Params: { agentId: string } }>("/api/owner/agents/:agentId", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-cards", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    if (!validAgentId(request.params.agentId)) throw uuidError();
    const agentId = request.params.agentId;
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "expectedRevision", "name", "description", "clientMetadata", "declaredVersion"]);
    const opId = parseOperationId(body.operationId);
    const expectedRevision = parseRevision(body.expectedRevision, "expectedRevision");
    const hasName = Object.hasOwn(body, "name");
    const hasDescription = Object.hasOwn(body, "description");
    const hasMetadata = Object.hasOwn(body, "clientMetadata");
    const hasVersion = Object.hasOwn(body, "declaredVersion");
    if (!hasName && !hasDescription && !hasMetadata && !hasVersion) {
      throw new HttpError(400, "INVALID_REQUEST", "At least one profile field must be changed");
    }
    const nameChange = hasName ? parseText(body.name, "name", 80) : undefined;
    const descriptionChange = hasDescription ? parseText(body.description, "description", 2000, true) : undefined;
    const metadataChange = hasMetadata
      ? (body.clientMetadata === null ? null : parseMetadataPatch(body.clientMetadata))
      : undefined;
    const versionChange = hasVersion ? parseOptionalNullableText(body.declaredVersion, "declaredVersion", 80) : undefined;
    const changes = {
      ...(hasName ? { name: nameChange! } : {}),
      ...(hasDescription ? { description: descriptionChange! } : {}),
      ...(hasMetadata ? { clientMetadata: metadataChange! } : {}),
      ...(hasVersion ? { declaredVersion: versionChange! } : {})
    };
    const payloadHash = hashPayload({ expectedRevision, changes });
    const ownAgent = await dependencies.db.query.agentProfiles.findFirst({ where: and(
      eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
    ) });
    if (!ownAgent) throw uuidError();

    const result = await dependencies.db.transaction(async (tx) => {
      const replay = await claimOperation(tx, {
        operationId: opId, ownerId: context.owner.id, agentId,
        action: "agent.profile.update", payloadHash
      });
      if (replay) return { card: replay, replayed: true };

      const lockedProfile = await lockOwnedProfile(tx, agentId, context.owner.id);
      if (lockedProfile.revision !== expectedRevision) {
        throw new HttpError(409, "REVISION_CONFLICT", "The agent profile changed; refresh before retrying");
      }

      let clientMetadata: { clientName: string | null; modelName: string | null } | undefined;
      if (hasMetadata) {
        const metadataPatch = metadataChange!;
        const currentMetadata = normalizeMetadata(lockedProfile.clientMetadata);
        clientMetadata = metadataPatch === null
          ? { clientName: null, modelName: null }
          : {
            clientName: metadataPatch.clientName === undefined ? currentMetadata.clientName : metadataPatch.clientName,
            modelName: metadataPatch.modelName === undefined ? currentMetadata.modelName : metadataPatch.modelName
          };
      }
      const [profile] = await tx.update(agentProfiles).set({
        revision: sql`${agentProfiles.revision} + 1`,
        updatedAt: new Date(),
        ...(hasName ? { name: nameChange! } : {}),
        ...(hasDescription ? { description: descriptionChange! } : {}),
        ...(hasMetadata ? { clientMetadata: clientMetadata! } : {}),
        ...(hasVersion ? { declaredVersion: versionChange! } : {})
      }).where(and(
        eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id), eq(agentProfiles.revision, expectedRevision)
      )).returning();
      if (!profile) {
        const current = await tx.query.agentProfiles.findFirst({ where: and(
          eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
        ) });
        if (!current) throw uuidError();
        throw new HttpError(409, "REVISION_CONFLICT", "The agent profile changed; refresh before retrying");
      }
      const policy = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, agentId) });
      if (!policy) throw new Error("Agent policy row is missing");
      const card = toAgentCard(profile, policy);
      await saveOperation(tx, opId, agentId, card);
      await audit(tx, "agent.profile_updated", opId, context.owner.id, agentId, card, Object.keys(changes));
      return { card, replayed: false };
    });
    return reply.header("Cache-Control", "no-store").send({ agent: result.card });
  });

  app.put<{ Params: { agentId: string } }>("/api/owner/agents/:agentId/permissions", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-cards", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    if (!validAgentId(request.params.agentId)) throw uuidError();
    const agentId = request.params.agentId;
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "expectedPolicyRevision", "permissions"]);
    const opId = parseOperationId(body.operationId);
    const expectedPolicyRevision = parseRevision(body.expectedPolicyRevision, "expectedPolicyRevision");
    const permissions = parsePermissionObject(body.permissions, false) as PermissionSet;
    const payloadHash = hashPayload({ expectedPolicyRevision, permissions });
    const ownAgent = await dependencies.db.query.agentProfiles.findFirst({ where: and(
      eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
    ) });
    if (!ownAgent) throw uuidError();

    const result = await dependencies.db.transaction(async (tx) => {
      const replay = await claimOperation(tx, {
        operationId: opId, ownerId: context.owner.id, agentId,
        action: "agent.permissions.update", payloadHash
      });
      if (replay) return { card: replay, replayed: true };

      await lockOwnedProfile(tx, agentId, context.owner.id);

      const [policy] = await tx.update(agentPolicies).set({
        training: permissions.training,
        ranked: permissions.ranked,
        forumMessages: permissions.forumMessages,
        customTopics: permissions.customTopics,
        revision: sql`${agentPolicies.revision} + 1`,
        updatedAt: new Date()
      }).where(and(eq(agentPolicies.agentId, agentId), eq(agentPolicies.revision, expectedPolicyRevision))).returning();
      if (!policy) {
        const current = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, agentId) });
        if (!current) throw uuidError();
        throw new HttpError(409, "REVISION_CONFLICT", "The agent permissions changed; refresh before retrying");
      }
      const profile = await tx.query.agentProfiles.findFirst({ where: and(
        eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
      ) });
      if (!profile) throw uuidError();
      const card = toAgentCard(profile, policy);
      await saveOperation(tx, opId, agentId, card);
      await audit(tx, "agent.permissions_updated", opId, context.owner.id, agentId, card, permissionKeys.map((key) => `permissions.${key}`));
      return { card, replayed: false };
    });
    return reply.header("Cache-Control", "no-store").send({ agent: result.card });
  });

  app.get<{ Params: { agentId: string } }>("/api/owner/agents/:agentId/manual-credential", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-credentials", dependencies.credentialRateLimitMax);
    const context = await admittedOwner(request, dependencies);
    const agentId = request.params.agentId;
    if (!validAgentId(agentId)) throw uuidError();
    const profile = await dependencies.db.query.agentProfiles.findFirst({ where: and(
      eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
    ) });
    if (!profile) throw uuidError();

    const rows = await dependencies.db.select({ grant: agentAccessGrants, credential: agentManualCredentials })
      .from(agentAccessGrants)
      .innerJoin(agentManualCredentials, eq(agentAccessGrants.id, agentManualCredentials.grantId))
      .where(and(eq(agentAccessGrants.agentId, agentId), eq(agentAccessGrants.ownerId, context.owner.id)))
      .orderBy(desc(agentAccessGrants.createdAt));
    const now = new Date();
    return reply.header("Cache-Control", "no-store").send({
      access: accessView(profile),
      resource: dependencies.agentResource,
      preflightUrl: dependencies.agentPreflightUrl,
      credentials: rows.map(({ grant, credential }) => credentialView(grant, credential, now))
    });
  });

  app.post<{ Params: { agentId: string } }>("/api/owner/agents/:agentId/manual-credential", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-credentials", dependencies.credentialRateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const agentId = request.params.agentId;
    if (!validAgentId(agentId)) throw uuidError();
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "expectedAccessRevision", "intent", "expiresInSeconds"]);
    const opId = parseOperationId(body.operationId);
    const expectedAccessRevision = parseRevision(body.expectedAccessRevision, "expectedAccessRevision");
    const intent = parseCredentialIntent(body.intent);
    const ttlSeconds = parseManualCredentialTtl(body.expiresInSeconds, dependencies.manualCredentialTtlSeconds);
    const payloadHash = hashPayload({
      expectedAccessRevision,
      intent,
      expiresInSeconds: body.expiresInSeconds === undefined ? null : ttlSeconds
    });
    const ownedProfile = await dependencies.db.query.agentProfiles.findFirst({ where: and(
      eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
    ) });
    if (!ownedProfile) throw uuidError();

    const result = await dependencies.db.transaction(async (tx) => {
      const replay = await claimSafeOperation(tx, {
        operationId: opId, ownerId: context.owner.id, agentId,
        action: `agent.manual_credential.${intent}`, payloadHash
      });
      if (replay) return { receipt: replay, replayed: true };

      const lockedProfile = await lockOwnedProfile(tx, agentId, context.owner.id);

      if (lockedProfile.accessRevision !== expectedAccessRevision) {
        throw new HttpError(409, "ACCESS_REVISION_CONFLICT", "The agent access state changed; refresh before retrying");
      }
      if (lockedProfile.accessRevokedAt) {
        throw new HttpError(409, "REAUTHORIZATION_REQUIRED", "The agent was globally revoked and requires a new owner authorization");
      }

      const priorGrants = await tx.query.agentAccessGrants.findMany({ where: and(
        eq(agentAccessGrants.ownerId, context.owner.id),
        eq(agentAccessGrants.agentId, agentId),
        eq(agentAccessGrants.source, "manual")
      ) });
      if (intent === "issue" && priorGrants.length > 0) {
        throw new HttpError(409, "CREDENTIAL_EXISTS", "Use replace to fence the previous manual credential");
      }

      const now = new Date();
      if (intent === "replace") {
        await tx.update(agentAccessGrants).set({ revokedAt: now, revocationReason: "replaced" })
          .where(and(
            eq(agentAccessGrants.ownerId, context.owner.id),
            eq(agentAccessGrants.agentId, agentId),
            eq(agentAccessGrants.source, "manual"),
            isNull(agentAccessGrants.revokedAt)
          ));
      }

      const [updatedProfile] = await tx.update(agentProfiles).set({
        accessRevision: sql`${agentProfiles.accessRevision} + 1`
      }).where(and(
        eq(agentProfiles.id, agentId),
        eq(agentProfiles.ownerId, context.owner.id),
        eq(agentProfiles.accessRevision, expectedAccessRevision),
        isNull(agentProfiles.accessRevokedAt)
      )).returning();
      if (!updatedProfile) throw new HttpError(409, "ACCESS_REVISION_CONFLICT", "The agent access state changed; refresh before retrying");

      const secret = `${manualCredentialPrefix}${randomBytes(32).toString("base64url")}`;
      const verifierHash = createHash("sha256").update(secret).digest("hex");
      const grantId = randomUUID();
      const credentialId = randomUUID();
      const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
      const [grant] = await tx.insert(agentAccessGrants).values({
        id: grantId,
        ownerId: context.owner.id,
        agentId,
        operationId: opId,
        source: "manual",
        resource: dependencies.agentResource,
        role: "agent",
        accessGeneration: updatedProfile.accessGeneration,
        createdAt: now,
        expiresAt,
        revokedAt: null,
        revocationReason: null
      }).returning();
      const [credential] = await tx.insert(agentManualCredentials).values({
        id: credentialId,
        grantId,
        verifierHash,
        createdAt: now
      }).returning();
      if (!grant || !credential) throw new Error("Manual credential issuance did not return persisted rows");

      const policy = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, agentId) });
      if (!policy) throw new Error("Agent policy row is missing");
      const receipt = {
        access: accessView(updatedProfile),
        credential: credentialView(grant, credential, now)
      };
      await saveOperationReceipt(tx, opId, agentId, receipt);
      await auditAccess(
        tx,
        intent === "issue" ? "agent.manual_credential.issued" : "agent.manual_credential.replaced",
        opId,
        context.owner.id,
        agentId,
        policy.revision,
        {
          accessRevision: updatedProfile.accessRevision,
          accessGeneration: updatedProfile.accessGeneration,
          grantId,
          credentialId,
          resource: dependencies.agentResource,
          role: "agent",
          expiresAt: expiresAt.toISOString()
        }
      );
      return { receipt, secret, replayed: false };
    });

    if (result.replayed) {
      return reply.header("Cache-Control", "no-store").send({
        ...result.receipt,
        replayed: true,
        secretAvailable: false
      });
    }
    return reply.code(intent === "issue" ? 201 : 200).header("Cache-Control", "no-store").send({
      ...result.receipt,
      secret: result.secret,
      replayed: false,
      secretAvailable: true
    });
  });

  app.post<{ Params: { agentId: string } }>("/api/owner/agents/:agentId/access-revoke", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-credentials", dependencies.credentialRateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const agentId = request.params.agentId;
    if (!validAgentId(agentId)) throw uuidError();
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "expectedAccessRevision"]);
    const opId = parseOperationId(body.operationId);
    const expectedAccessRevision = parseRevision(body.expectedAccessRevision, "expectedAccessRevision");
    const payloadHash = hashPayload({ expectedAccessRevision, intent: "global-revoke" });
    const ownedProfile = await dependencies.db.query.agentProfiles.findFirst({ where: and(
      eq(agentProfiles.id, agentId), eq(agentProfiles.ownerId, context.owner.id)
    ) });
    if (!ownedProfile) throw uuidError();

    const result = await dependencies.db.transaction(async (tx) => {
      const replay = await claimSafeOperation(tx, {
        operationId: opId, ownerId: context.owner.id, agentId,
        action: "agent.access.revoke", payloadHash
      });
      if (replay) return { receipt: replay, replayed: true };
      const lockedProfile = await lockOwnedProfile(tx, agentId, context.owner.id);
      if (lockedProfile.accessRevision !== expectedAccessRevision) {
        throw new HttpError(409, "ACCESS_REVISION_CONFLICT", "The agent access state changed; refresh before retrying");
      }
      if (lockedProfile.accessRevokedAt) {
        throw new HttpError(409, "ACCESS_ALREADY_REVOKED", "The agent access was already globally revoked");
      }

      const now = new Date();
      const nextGeneration = lockedProfile.accessGeneration + 1;
      const [updatedProfile] = await tx.update(agentProfiles).set({
        accessRevision: sql`${agentProfiles.accessRevision} + 1`,
        accessGeneration: sql`${agentProfiles.accessGeneration} + 1`,
        accessRevokedAt: now
      }).where(and(
        eq(agentProfiles.id, agentId),
        eq(agentProfiles.ownerId, context.owner.id),
        eq(agentProfiles.accessRevision, expectedAccessRevision),
        isNull(agentProfiles.accessRevokedAt)
      )).returning();
      if (!updatedProfile) throw new HttpError(409, "ACCESS_REVISION_CONFLICT", "The agent access state changed; refresh before retrying");

      await tx.update(agentAccessGrants).set({ revokedAt: now, revocationReason: "owner_global_revoke" })
        .where(and(
          eq(agentAccessGrants.ownerId, context.owner.id),
          eq(agentAccessGrants.agentId, agentId),
          isNull(agentAccessGrants.revokedAt)
        ));
      const eventId = randomUUID();
      const [event] = await tx.insert(agentCancellationOutbox).values({
        eventId,
        ownerId: context.owner.id,
        agentId,
        accessGeneration: nextGeneration,
        operationId: opId,
        eventType: "agent.access.revoked",
        status: "pending",
        payloadJson: { scope: "all", reason: "owner_global_revoke" },
        createdAt: now
      }).returning();
      const policy = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, agentId) });
      if (!policy) throw new Error("Agent policy row is missing");
      const receipt = {
        access: accessView(updatedProfile),
        cancellation: {
          eventId: event?.eventId ?? eventId,
          status: "pending" as const,
          createdAt: (event?.createdAt ?? now).toISOString()
        }
      };
      await saveOperationReceipt(tx, opId, agentId, receipt);
      await auditAccess(tx, "agent.access.revoked", opId, context.owner.id, agentId, policy.revision, {
        accessRevision: updatedProfile.accessRevision,
        accessGeneration: updatedProfile.accessGeneration,
        cancellationEventId: eventId,
        cancellationStatus: "pending",
        scope: "all",
        reason: "owner_global_revoke"
      });
      return { receipt, replayed: false };
    });
    return reply.header("Cache-Control", "no-store").send({ ...result.receipt, replayed: result.replayed });
  });

  app.get("/api/agent/preflight", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-preflight-ip", dependencies.preflightRateLimitMax);
    const authorization = request.headers.authorization;
    const match = typeof authorization === "string" ? /^Bearer (aap1_[A-Za-z0-9_-]{43})$/.exec(authorization) : null;
    if (!match) throw new HttpError(401, "UNAUTHORIZED", "A valid agent bearer credential is required");

    const tokenHash = createHash("sha256").update(match[1]!).digest("hex");
    const rows = await dependencies.db.select({
      credentialId: agentManualCredentials.id,
      ownerId: agentAccessGrants.ownerId,
      agentId: agentAccessGrants.agentId,
      resource: agentAccessGrants.resource,
      role: agentAccessGrants.role,
      grantGeneration: agentAccessGrants.accessGeneration,
      grantExpiresAt: agentAccessGrants.expiresAt,
      grantRevokedAt: agentAccessGrants.revokedAt,
      accessGeneration: agentProfiles.accessGeneration,
      accessRevision: agentProfiles.accessRevision,
      accessRevokedAt: agentProfiles.accessRevokedAt,
      policyRevision: agentPolicies.revision,
      training: agentPolicies.training,
      ranked: agentPolicies.ranked,
      forumMessages: agentPolicies.forumMessages,
      customTopics: agentPolicies.customTopics
    }).from(agentManualCredentials)
      .innerJoin(agentAccessGrants, eq(agentManualCredentials.grantId, agentAccessGrants.id))
      .innerJoin(agentProfiles, eq(agentAccessGrants.agentId, agentProfiles.id))
      .innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
      .where(eq(agentManualCredentials.verifierHash, tokenHash))
      .limit(1);
    const row = rows[0];
    if (!row) throw new HttpError(401, "UNAUTHORIZED", "A valid agent bearer credential is required");
    await dependencies.rateLimit(request, `agent-preflight-${row.credentialId}`, dependencies.preflightRateLimitMax);
    const now = new Date();
    if (row.role !== "agent" || row.grantRevokedAt || row.accessRevokedAt ||
      row.grantGeneration !== row.accessGeneration || row.grantExpiresAt <= now) {
      throw new HttpError(401, "UNAUTHORIZED", "The agent bearer credential is expired or revoked");
    }

    const requestedAgent = request.headers["x-agent-id"];
    const requestedResource = request.headers["x-agent-resource"];
    if (typeof requestedAgent !== "string" || requestedAgent !== row.agentId ||
      row.resource !== dependencies.agentResource ||
      typeof requestedResource !== "string" || requestedResource !== row.resource) {
      throw new HttpError(403, "FORBIDDEN", "The credential is not bound to the requested agent and resource");
    }
    return reply.header("Cache-Control", "no-store").send({
      allowed: true,
      agentId: row.agentId,
      resource: row.resource,
      role: row.role,
      accessRevision: row.accessRevision,
      policyRevision: row.policyRevision,
      permissions: {
        training: row.training,
        ranked: row.ranked,
        forumMessages: row.forumMessages,
        customTopics: row.customTopics
      }
    });
  });
}
