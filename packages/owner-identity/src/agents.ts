import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { isIP } from "node:net";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { selectAgentMcpTransport } from "./agent-mcp-profile.js";
import { reportUploadChunkSchema } from "./report-service.js";
import { withOAuthSelection, type OAuthSelectionContext } from "./auth.js";
import type { createAuth } from "./auth.js";
import { findMcpClient, type OwnerIdentityConfig } from "./config.js";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import {
  agentOperations,
  agentPolicies,
  agentProfiles,
  agentAccessGrants,
  agentManualCredentials,
  agentCancellationOutbox,
  agentOauthAuthorizations,
  oauthClients,
  owners,
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
  owner: { id: string; authUserId: string; admissionStatus: string };
}

export interface AgentRouteDependencies {
  db: OwnerDatabase;
  auth: ReturnType<typeof createAuth>;
  config: OwnerIdentityConfig;
  resolveOwner(request: FastifyRequest): Promise<AgentOwnerContext>;
  requireOrigin(request: FastifyRequest): Promise<void>;
  rateLimit(request: FastifyRequest, group: string, limit: number): Promise<void>;
  rateLimitMax: number;
  credentialRateLimitMax: number;
  preflightRateLimitMax: number;
  manualCredentialTtlSeconds: number;
  agentResource: string;
  agentPreflightUrl: string;
  registerMcpTools?: (server: McpServer, principal: AgentPrincipal) => void;
}

/** Hosts accepted by authenticated agent HTTP ingress on the configured API listener. */
export function allowedAgentRequestHosts(config: Pick<OwnerIdentityConfig, "publicOrigin" | "apiHost" | "apiPort">): ReadonlySet<string> {
  const configuredApiHost = config.apiHost.trim().toLowerCase().replace(/^\[|\]$/g, "");
  const addressHost = isIP(configuredApiHost) === 6 ? `[${configuredApiHost}]` : configuredApiHost;
  return new Set([
    new URL(config.publicOrigin).host.toLowerCase(),
    `127.0.0.1:${config.apiPort}`,
    `localhost:${config.apiPort}`,
    `[::1]:${config.apiPort}`,
    ...(configuredApiHost === "0.0.0.0" || configuredApiHost === "::" ? [] : [`${addressHost}:${config.apiPort}`]),
  ]);
}

interface VerifiedOAuthRequest {
  query: string;
  queryHash: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  state: string;
}

async function parseOAuthQuery(value: unknown, dependencies: AgentRouteDependencies): Promise<VerifiedOAuthRequest> {
  if (typeof value !== "string" || value.length < 1 || value.length > 8192) {
    throw new HttpError(400, "INVALID_OAUTH_QUERY", "The signed OAuth request is missing or too large");
  }
  const query = value.startsWith("?") ? value.slice(1) : value;
  if (!query || !(await verifyOAuthQueryParams(query, dependencies.config.authSecret))) {
    throw new HttpError(400, "INVALID_OAUTH_QUERY", "The signed OAuth request is invalid or expired");
  }
  const params = new URLSearchParams(query);
  const resources = params.getAll("resource");
  const scopeValue = params.get("scope") ?? "";
  const scopes = scopeValue.split(/\s+/).filter(Boolean);
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const state = params.get("state") ?? "";
  const challenge = params.get("code_challenge") ?? "";
  const nonceValues = params.getAll("nonce");
  const registeredClient = findMcpClient(dependencies.config, clientId);
  if (params.get("response_type") !== "code" || params.getAll("response_type").length !== 1 ||
    params.getAll("client_id").length !== 1 || !registeredClient || !registeredClient.redirectUris.includes(redirectUri) ||
    params.getAll("redirect_uri").length !== 1 ||
    params.get("code_challenge_method") !== "S256" || params.getAll("code_challenge_method").length !== 1 ||
    params.getAll("code_challenge").length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
    !state || state.length > 512 || params.getAll("state").length !== 1 || resources.length !== 1 || resources[0] !== dependencies.agentResource ||
    params.getAll("scope").length !== 1 || scopes.length !== 1 || scopes[0] !== "agent:operate") {
    throw new HttpError(400, "OAUTH_REQUEST_NOT_SUPPORTED", "Only a registered public client, its exact callback, S256 PKCE, the agent resource, and agent:operate scope are supported");
  }
  if (nonceValues.length > 1 || (nonceValues[0] !== undefined && (nonceValues[0].length < 1 || nonceValues[0].length > 512))) {
    throw new HttpError(400, "OAUTH_REQUEST_NOT_SUPPORTED", "OAuth nonce must be a single value no longer than 512 characters");
  }
  const queryHash = createHash("sha256").update(JSON.stringify({
    responseType: "code", clientId, redirectUri, state,
    codeChallenge: challenge, codeChallengeMethod: "S256",
    resource: resources[0], scopes, ...(nonceValues[0] ? { nonce: nonceValues[0] } : {})
  })).digest("hex");
  return {
    query,
    queryHash,
    clientId,
    redirectUri,
    resource: resources[0]!,
    scopes,
    state
  };
}

function providerHeaders(request: FastifyRequest): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (value === undefined || ["host", "content-length", "connection", "transfer-encoding"].includes(key.toLowerCase())) continue;
    headers.set(key, Array.isArray(value) ? value.join(", ") : String(value));
  }
  headers.set("content-type", "application/json");
  return headers;
}

async function callOAuthProvider(request: FastifyRequest, dependencies: AgentRouteDependencies, endpoint: "continue" | "consent", body: Record<string, unknown>, selection: OAuthSelectionContext): Promise<Response> {
  const providerRequest = new Request(`${dependencies.config.publicOrigin}/api/auth/oauth2/${endpoint}`, {
    method: "POST", headers: providerHeaders(request), body: JSON.stringify(body)
  });
  return withOAuthSelection(selection, () => dependencies.auth.handler(providerRequest));
}

async function validatedProviderRedirect(response: Response, expectedOrigin: string, expectedPath: string): Promise<string> {
  if (!response.ok) {
    throw new HttpError(502, "OAUTH_PROVIDER_REDIRECT_MISSING", "The OAuth provider did not return the expected redirect");
  }
  let body: Record<string, unknown>;
  try {
    body = record(await response.json(), "OAuth provider response");
  } catch {
    throw new HttpError(502, "OAUTH_PROVIDER_REDIRECT_MISSING", "The OAuth provider did not return the expected redirect");
  }
  if (body.redirect !== true || typeof body.url !== "string") {
    throw new HttpError(502, "OAUTH_PROVIDER_REDIRECT_MISSING", "The OAuth provider did not return the expected redirect");
  }
  const url = new URL(body.url, expectedOrigin);
  if (url.origin !== expectedOrigin || url.pathname !== expectedPath || url.username || url.password || url.hash) {
    throw new HttpError(502, "OAUTH_PROVIDER_REDIRECT_INVALID", "The OAuth provider returned an unexpected redirect destination");
  }
  return url.toString();
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

export interface AgentPrincipal {
  credentialSource?: "manual" | "oauth";
  oauthClientId?: string;
  ownerId: string;
  agentId: string;
  grantId: string;
  credentialId: string;
  resource: string;
  role: string;
  accessGeneration: number;
  accessRevision: number;
  policyRevision: number;
  permissions: PermissionSet;
}

function bearerChallenge(dependencies: AgentRouteDependencies): string {
  const metadataUrl = `${dependencies.config.publicOrigin}/.well-known/oauth-protected-resource/api/agent`;
  return `Bearer resource_metadata="${metadataUrl}", scope="agent:operate"`;
}

function isValidatedSupportScreenshotChunk(body: unknown): boolean {
  const message = body !== null && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  const params = message.params !== null && typeof message.params === "object" && !Array.isArray(message.params)
    ? message.params as Record<string, unknown> : {};
  return message.jsonrpc === "2.0" && message.method === "tools/call" && params.name === "support.screenshot.chunk" &&
    reportUploadChunkSchema.safeParse(params.arguments).success;
}

export async function resolveAgentPrincipal(dependencies: AgentRouteDependencies, bearer: string): Promise<AgentPrincipal | undefined> {
  const now = new Date();
  const manual = /^aap1_[A-Za-z0-9_-]{43}$/.test(bearer);
  if (manual) {
    const tokenHash = createHash("sha256").update(bearer).digest("hex");
    const rows = await dependencies.db.select({
      credentialId: agentManualCredentials.id,
      grantId: agentAccessGrants.id,
      ownerId: agentAccessGrants.ownerId,
      agentId: agentAccessGrants.agentId,
      resource: agentAccessGrants.resource,
      role: agentAccessGrants.role,
      grantGeneration: agentAccessGrants.accessGeneration,
      grantExpiresAt: agentAccessGrants.expiresAt,
      grantRevokedAt: agentAccessGrants.revokedAt,
      source: agentAccessGrants.source,
      accessGeneration: agentProfiles.accessGeneration,
      accessRevision: agentProfiles.accessRevision,
      accessRevokedAt: agentProfiles.accessRevokedAt,
      admissionStatus: owners.admissionStatus,
      training: agentPolicies.training,
      ranked: agentPolicies.ranked,
      forumMessages: agentPolicies.forumMessages,
      customTopics: agentPolicies.customTopics,
      policyRevision: agentPolicies.revision
    }).from(agentManualCredentials)
      .innerJoin(agentAccessGrants, eq(agentManualCredentials.grantId, agentAccessGrants.id))
      .innerJoin(agentProfiles, eq(agentAccessGrants.agentId, agentProfiles.id))
      .innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
      .innerJoin(owners, eq(agentAccessGrants.ownerId, owners.id))
      .where(and(eq(agentManualCredentials.verifierHash, tokenHash), eq(agentAccessGrants.source, "manual")))
      .limit(1);
    const row = rows[0];
    if (!row || row.role !== "agent" || row.admissionStatus !== "admitted" || row.grantRevokedAt || row.accessRevokedAt ||
      row.grantGeneration !== row.accessGeneration || row.grantExpiresAt <= now || row.resource !== dependencies.agentResource) return undefined;
    return {
      credentialSource: "manual",
      ownerId: row.ownerId, agentId: row.agentId, grantId: row.grantId, credentialId: row.credentialId,
      resource: row.resource, role: row.role, accessGeneration: row.accessGeneration, accessRevision: row.accessRevision,
      policyRevision: row.policyRevision,
      permissions: { training: row.training, ranked: row.ranked, forumMessages: row.forumMessages, customTopics: row.customTopics }
    };
  }

  if (bearer.length > 8192 || bearer.split(".").length !== 3) return undefined;
  let payload: Record<string, unknown>;
  try {
    const verified = await dependencies.auth.api.verifyJWT({ body: { token: bearer, issuer: `${dependencies.config.publicOrigin}/api/auth` } });
    if (!verified.payload) return undefined;
    payload = verified.payload as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const audience = payload.aud;
  const resourceMatches = audience === dependencies.agentResource ||
    (Array.isArray(audience) && audience.length === 1 && audience[0] === dependencies.agentResource);
  const generation = payload.oid_access_generation;
  const ownerId = payload.oid_owner_id;
  const agentId = payload.oid_agent_id;
  const grantId = payload.oid_grant_id;
  const oauthClientId = payload.azp;
  const registeredClient = typeof oauthClientId === "string" ? findMcpClient(dependencies.config, oauthClientId) : undefined;
  if (!resourceMatches || payload.iss !== `${dependencies.config.publicOrigin}/api/auth` ||
    !registeredClient || payload.scope !== "agent:operate" || payload.oid_role !== "agent" ||
    typeof payload.sub !== "string" || typeof ownerId !== "string" || typeof agentId !== "string" || typeof grantId !== "string" ||
    typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1) return undefined;

  const rows = await dependencies.db.select({
    ownerId: agentAccessGrants.ownerId,
    agentId: agentAccessGrants.agentId,
    grantId: agentAccessGrants.id,
    oauthClientId: agentAccessGrants.oauthClientId,
    resource: agentAccessGrants.resource,
    role: agentAccessGrants.role,
    grantGeneration: agentAccessGrants.accessGeneration,
    grantExpiresAt: agentAccessGrants.expiresAt,
    grantRevokedAt: agentAccessGrants.revokedAt,
    accessGeneration: agentProfiles.accessGeneration,
    accessRevision: agentProfiles.accessRevision,
    accessRevokedAt: agentProfiles.accessRevokedAt,
    admissionStatus: owners.admissionStatus,
    authUserId: owners.authUserId,
    authorizationId: agentOauthAuthorizations.id,
    authorizationStatus: agentOauthAuthorizations.status,
    authorizationCodeHash: agentOauthAuthorizations.authorizationCodeHash,
    authorizationGeneration: agentOauthAuthorizations.accessGeneration,
    authorizationClientId: agentOauthAuthorizations.clientId,
    authorizationResource: agentOauthAuthorizations.resource,
    training: agentPolicies.training,
    ranked: agentPolicies.ranked,
    forumMessages: agentPolicies.forumMessages,
    customTopics: agentPolicies.customTopics,
    policyRevision: agentPolicies.revision
  }).from(agentAccessGrants)
    .innerJoin(agentOauthAuthorizations, eq(agentOauthAuthorizations.grantId, agentAccessGrants.id))
    .innerJoin(agentProfiles, eq(agentAccessGrants.agentId, agentProfiles.id))
    .innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
    .innerJoin(owners, eq(agentAccessGrants.ownerId, owners.id))
    .where(and(eq(agentAccessGrants.id, grantId), eq(agentAccessGrants.source, "oauth"), eq(agentOauthAuthorizations.status, "approved")))
    .limit(1);
  const row = rows[0];
  if (!row || row.ownerId !== ownerId || row.agentId !== agentId || row.authUserId !== payload.sub ||
    row.oauthClientId !== oauthClientId || row.authorizationClientId !== oauthClientId ||
    row.resource !== dependencies.agentResource || row.authorizationResource !== row.resource || row.role !== "agent" ||
    row.authorizationCodeHash === null || row.admissionStatus !== "admitted" || row.grantRevokedAt || row.accessRevokedAt ||
    row.grantGeneration !== row.accessGeneration || row.grantGeneration !== generation || row.authorizationGeneration !== generation ||
    row.grantExpiresAt <= now) return undefined;
  return {
    credentialSource: "oauth",
    oauthClientId: oauthClientId as string,
    ownerId: row.ownerId, agentId: row.agentId, grantId: row.grantId, credentialId: row.grantId,
    resource: row.resource, role: row.role, accessGeneration: row.accessGeneration, accessRevision: row.accessRevision,
    policyRevision: row.policyRevision,
    permissions: { training: row.training, ranked: row.ranked, forumMessages: row.forumMessages, customTopics: row.customTopics }
  };
}

export function registerAgentRoutes(app: FastifyInstance, dependencies: AgentRouteDependencies) {
  app.all("/api/agent/mcp", { bodyLimit: 64 * 1024 }, async (request, reply) => {
    if (request.method !== "POST") return reply.code(405).header("Allow", "POST").send({ error: "method_not_allowed" });
    const host = request.headers.host?.toLowerCase();
    const allowedHosts = allowedAgentRequestHosts(dependencies.config);
    if (!host || !allowedHosts.has(host)) return reply.code(421).send({ error: "misdirected_request" });
    const origin = request.headers.origin;
    if (origin && origin !== dependencies.config.publicOrigin) return reply.code(403).send({ error: "origin_not_allowed" });
    const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") return reply.code(415).send({ error: "unsupported_media_type" });
    const authorization = request.headers.authorization;
    const match = typeof authorization === "string" ? /^Bearer ([^\s]{1,8192})$/.exec(authorization) : null;
    if (!match) return reply.code(401).header("WWW-Authenticate", bearerChallenge(dependencies)).send({ error: "unauthorized" });

    // MCP upload chunks may require up to 214 ordered requests for one 5 MiB image.
    // Keep all MCP traffic IP-bounded at 300/min; the per-credential 60/min default
    // remains in force except for the schema-validated screenshot chunk tool below.
    await dependencies.rateLimit(request, "agent-mcp-ip", 300);
    const principal = await resolveAgentPrincipal(dependencies, match[1]!);
    if (!principal) return reply.code(401).header("WWW-Authenticate", bearerChallenge(dependencies)).send({ error: "unauthorized" });

    const selectedTransport = selectAgentMcpTransport(dependencies.config,
      principal.credentialSource === "manual", request.body, request.headers, principal.oauthClientId);
    const localCodexTransport = selectedTransport === "codex-local";
    const betaRemoteTransport = selectedTransport === "beta-remote";
    if (betaRemoteTransport && isValidatedSupportScreenshotChunk(request.body)) {
      await dependencies.rateLimit(request, "agent-mcp-screenshot-chunk-ip", 300);
      await dependencies.rateLimit(request, `agent-mcp-screenshot-chunk-${principal.credentialId}`, 300);
    } else {
      await dependencies.rateLimit(request, `agent-preflight-${principal.credentialId}`, dependencies.preflightRateLimitMax);
    }
    const outputSchema = z.object({
      status: z.enum(["allowed", "denied"]),
      operationId: z.string(),
      policyVersion: z.number().int(),
      accessGeneration: z.number().int()
    });
    const mcpHandler = createMcpHandler(() => {
      const server = new McpServer({ name: "Web3 Agent Bench", version: "1.0.0" }, {
        supportedProtocolVersions: localCodexTransport ? ["2026-07-28", "2025-06-18"] : betaRemoteTransport
          ? [...new Set(dependencies.config.betaManifest?.clients.filter((profile) => profile.enabled)
            .flatMap((profile) => profile.protocolVersions) ?? ["2026-07-28"])]
          : ["2026-07-28"],
        maxToolInputElements: 8
      });
      server.registerTool("identity.preflight", {
        title: "Check agent connection",
        description: "Check this fixed agent connection and report the current policy revision. This free check does not authorize a paid or public action.",
        inputSchema: z.object({
          agentId: z.string().uuid(),
          operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/)
        }),
        outputSchema
      }, async ({ agentId, operationId }) => {
        const result = {
          status: agentId === principal.agentId ? "allowed" as const : "denied" as const,
          operationId,
          policyVersion: principal.policyRevision,
          accessGeneration: principal.accessGeneration
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }], structuredContent: result };
      });
      dependencies.registerMcpTools?.(server, principal);
      return server;
    }, { legacy: localCodexTransport || betaRemoteTransport ? "stateless" : "reject",
      responseMode: "json", keepAliveMs: 0, maxRequestBodySize: 64 * 1024 });

    const headers = new Headers();
    for (const key of ["accept", "authorization", "content-type", "mcp-protocol-version", "mcp-method", "mcp-name", "mcp-session-id", "last-event-id", "origin", "user-agent"]) {
      const value = request.headers[key];
      if (typeof value === "string") headers.set(key, value);
    }
    const webRequest = new Request(new URL(request.url, dependencies.config.publicOrigin), {
      method: "POST", headers, body: JSON.stringify(request.body)
    });
    try {
      const response = await mcpHandler.fetch(webRequest, { parsedBody: request.body });
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Cache-Control", "no-store");
      responseHeaders.forEach((value, key) => reply.header(key, value));
      return reply.code(response.status).send(Buffer.from(await response.arrayBuffer()));
    } finally {
      await mcpHandler.close().catch(() => undefined);
    }
  });

  app.post("/api/owner/agents/oauth-select", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-oauth-consent", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "oauth_query", "agentId"]);
    const operationId = parseOperationId(body.operationId);
    const agentId = typeof body.agentId === "string" ? body.agentId : "";
    if (!validAgentId(agentId)) throw uuidError();
    const signed = await parseOAuthQuery(body.oauth_query, dependencies);
    const auth = await dependencies.resolveOwner(request);
    const session = await dependencies.auth.api.getSession({ headers: providerHeaders(request) });
    if (!session || session.user.id !== auth.owner.authUserId) throw new HttpError(401, "UNAUTHORIZED", "An authenticated owner session is required");
    const client = await dependencies.db.query.oauthClients.findFirst({ where: eq(oauthClients.clientId, signed.clientId) });
    const registeredClient = findMcpClient(dependencies.config, signed.clientId);
    if (!client || client.disabled || !registeredClient || !registeredClient.redirectUris.includes(signed.redirectUri)) {
      throw new HttpError(400, "OAUTH_CLIENT_NOT_REGISTERED", "The OAuth client is not registered");
    }
    const now = new Date();
    const flowId = randomUUID();
    const grantId = randomUUID();
    const selection: OAuthSelectionContext = {
      authUserId: session.user.id, authSessionId: session.session.id,
      ownerId: context.owner.id, agentId, grantId
    };
    await dependencies.db.transaction(async (tx) => {
      const profile = await lockOwnedProfile(tx, agentId, context.owner.id);
      if (profile.accessRevokedAt) throw new HttpError(403, "AGENT_ACCESS_REVOKED", "Agent access was globally revoked; create a fresh agent access grant before authorizing this client");
      const policy = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, agentId) });
      if (!policy) throw uuidError();
      await tx.insert(agentOauthAuthorizations).values({
        id: flowId, operationId, queryHash: signed.queryHash, ownerId: context.owner.id,
        authUserId: session.user.id, authSessionId: session.session.id, agentId, grantId,
        clientId: signed.clientId, resource: signed.resource, redirectUri: signed.redirectUri,
        scopes: signed.scopes, accessGeneration: profile.accessGeneration,
        policyRevision: policy.revision, authorizationCodeHash: null, status: "selected", createdAt: now,
        expiresAt: new Date(now.getTime() + 600_000), completedAt: null
      });
    });
    try {
      const providerResponse = await callOAuthProvider(request, dependencies, "continue", { postLogin: true, oauth_query: signed.query }, selection);
      const redirectUrl = await validatedProviderRedirect(providerResponse, dependencies.config.publicOrigin, "/owner/agents/oauth-consent");
      return reply.header("Cache-Control", "no-store").send({ redirectUrl });
    } catch (error) {
      await dependencies.db.transaction(async (tx) => {
        const failedAt = new Date();
        const changed = await tx.update(agentOauthAuthorizations).set({ status: "failed", completedAt: failedAt })
          .where(and(eq(agentOauthAuthorizations.id, flowId), eq(agentOauthAuthorizations.status, "selected")))
          .returning({ agentId: agentOauthAuthorizations.agentId, ownerId: agentOauthAuthorizations.ownerId, policyRevision: agentOauthAuthorizations.policyRevision });
        if (changed[0]) {
          await auditAccess(tx, "agent.oauth.selection_failed", `oauth-selection-failed:${flowId}`, changed[0].ownerId,
            changed[0].agentId, changed[0].policyRevision, { authorizationId: flowId, clientId: signed.clientId, reason: "provider_continuation_failed" });
        }
      }).catch(() => undefined);
      throw error;
    }
  });

  app.post("/api/owner/agents/oauth-consent-context", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-oauth-consent", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["oauth_query"]);
    const signed = await parseOAuthQuery(body.oauth_query, dependencies);
    const session = await dependencies.auth.api.getSession({ headers: providerHeaders(request) });
    const flow = await dependencies.db.query.agentOauthAuthorizations.findFirst({ where: eq(agentOauthAuthorizations.queryHash, signed.queryHash) });
    if (!session || !flow || flow.ownerId !== context.owner.id || flow.authUserId !== session.user.id ||
      flow.authSessionId !== session.session.id || flow.clientId !== signed.clientId || flow.resource !== signed.resource ||
      flow.redirectUri !== signed.redirectUri) {
      throw new HttpError(403, "OAUTH_FLOW_MISMATCH", "This OAuth request is not bound to the current owner session");
    }
    if (flow.status !== "selected" || flow.completedAt) throw new HttpError(409, "OAUTH_FLOW_COMPLETED", "This OAuth request has already been decided");
    if (flow.expiresAt <= new Date()) throw new HttpError(410, "OAUTH_FLOW_EXPIRED", "This OAuth authorization request has expired");
    const rows = await dependencies.db.select({ profile: agentProfiles, policy: agentPolicies })
      .from(agentProfiles).innerJoin(agentPolicies, eq(agentProfiles.id, agentPolicies.agentId))
      .where(and(eq(agentProfiles.id, flow.agentId), eq(agentProfiles.ownerId, context.owner.id))).limit(1);
    const row = rows[0];
    if (!row) throw uuidError();
    if (row.profile.accessRevokedAt || row.profile.accessGeneration !== flow.accessGeneration) {
      throw new HttpError(409, "AGENT_ACCESS_CHANGED", "Agent access changed after this OAuth request began; restart authorization");
    }
    const client = await dependencies.db.query.oauthClients.findFirst({ where: eq(oauthClients.clientId, flow.clientId) });
    return reply.header("Cache-Control", "no-store").send({
      flowId: flow.id,
      client: { clientId: flow.clientId, name: client?.name ?? "Registered MCP client" },
      resource: flow.resource,
      scopes: flow.scopes,
      agent: {
        id: row.profile.id,
        name: row.profile.name,
        permissions: { training: row.policy.training, ranked: row.policy.ranked, forumMessages: row.policy.forumMessages, customTopics: row.policy.customTopics },
        policyRevision: row.policy.revision
      },
      expiresAt: flow.expiresAt.toISOString()
    });
  });

  app.post("/api/owner/agents/oauth-consent", async (request, reply) => {
    await dependencies.rateLimit(request, "agent-oauth-consent", dependencies.rateLimitMax);
    await dependencies.requireOrigin(request);
    const context = await admittedOwner(request, dependencies);
    const body = record(request.body, "body");
    rejectUnknownKeys(body, ["operationId", "flowId", "oauth_query", "accept", "expectedPolicyRevision"]);
    const operationId = parseOperationId(body.operationId);
    const flowId = typeof body.flowId === "string" && validAgentId(body.flowId) ? body.flowId : "";
    if (!flowId) throw new HttpError(400, "INVALID_OAUTH_FLOW", "flowId must be a UUID");
    if (typeof body.accept !== "boolean") throw new HttpError(400, "INVALID_DECISION", "accept must be a boolean");
    const expectedPolicyRevision = parseRevision(body.expectedPolicyRevision, "expectedPolicyRevision");
    const signed = await parseOAuthQuery(body.oauth_query, dependencies);
    const session = await dependencies.auth.api.getSession({ headers: providerHeaders(request) });
    if (!session) throw new HttpError(401, "UNAUTHORIZED", "An authenticated owner session is required");
    const flow = await dependencies.db.query.agentOauthAuthorizations.findFirst({ where: eq(agentOauthAuthorizations.id, flowId) });
    if (!flow || flow.ownerId !== context.owner.id || flow.authUserId !== session.user.id || flow.authSessionId !== session.session.id ||
      flow.queryHash !== signed.queryHash || flow.clientId !== signed.clientId || flow.resource !== signed.resource ||
      flow.redirectUri !== signed.redirectUri) {
      throw new HttpError(403, "OAUTH_FLOW_MISMATCH", "This OAuth decision does not match the selected owner, agent, session, and signed request");
    }
    if (flow.status !== "selected" || flow.completedAt) throw new HttpError(409, "OAUTH_FLOW_COMPLETED", "This OAuth request has already been decided");
    if (flow.expiresAt <= new Date()) throw new HttpError(410, "OAUTH_FLOW_EXPIRED", "This OAuth authorization request has expired");
    const selection: OAuthSelectionContext = {
      authUserId: session.user.id, authSessionId: session.session.id,
      ownerId: context.owner.id, agentId: flow.agentId, grantId: flow.grantId
    };
    await dependencies.db.transaction(async (tx) => {
      const locked = await lockOwnedProfile(tx, flow.agentId, context.owner.id);
      const lockedFlow = await tx.execute(sql`SELECT id FROM oid_agent_oauth_authorization WHERE id=${flow.id} FOR UPDATE`);
      if (lockedFlow.length !== 1) throw new HttpError(410, "OAUTH_FLOW_EXPIRED", "OAuth flow no longer exists");
      const currentFlow = await tx.query.agentOauthAuthorizations.findFirst({ where: eq(agentOauthAuthorizations.id, flow.id) });
      const policy = await tx.query.agentPolicies.findFirst({ where: eq(agentPolicies.agentId, flow.agentId) });
      if (!currentFlow || currentFlow.status !== "selected" || currentFlow.expiresAt <= new Date() || !policy ||
        currentFlow.authSessionId !== session.session.id || currentFlow.queryHash !== signed.queryHash) {
        throw new HttpError(409, "OAUTH_FLOW_COMPLETED", "OAuth flow changed while consent was being recorded");
      }
      if (policy.revision !== expectedPolicyRevision) throw new HttpError(409, "POLICY_CHANGED", "Agent permissions changed; review the updated policy before deciding");
      if (locked.accessRevokedAt || locked.accessGeneration !== flow.accessGeneration) {
        throw new HttpError(409, "AGENT_ACCESS_CHANGED", "Agent access changed after this OAuth request began; restart authorization");
      }
      const now = new Date();
      if (body.accept) {
        await tx.insert(agentAccessGrants).values({
          id: flow.grantId, ownerId: context.owner.id, agentId: flow.agentId,
          operationId: `oauth-${flow.id}`, source: "oauth", oauthClientId: flow.clientId,
          resource: flow.resource, role: "agent", accessGeneration: locked.accessGeneration,
          createdAt: now, expiresAt: new Date(now.getTime() + 3600_000), revokedAt: null, revocationReason: null
        });
      }
      const changed = await tx.update(agentOauthAuthorizations).set({
        status: body.accept ? "approved" : "denied", policyRevision: policy.revision, completedAt: now
      })
        .where(and(eq(agentOauthAuthorizations.id, flow.id), eq(agentOauthAuthorizations.status, "selected")))
        .returning({ id: agentOauthAuthorizations.id });
      if (changed.length !== 1) throw new HttpError(409, "OAUTH_FLOW_COMPLETED", "OAuth flow was already decided");
      await auditAccess(tx, body.accept ? "agent.oauth.consent_approved" : "agent.oauth.consent_denied",
        `oauth-consent:${flow.id}`, context.owner.id, flow.agentId, policy.revision, {
          authorizationId: flow.id, grantId: body.accept ? flow.grantId : null,
          clientId: flow.clientId, resource: flow.resource, scopes: flow.scopes,
          decision: body.accept ? "approved" : "denied"
        });
    });
    if (!body.accept) {
      const providerResponse = await callOAuthProvider(request, dependencies, "consent", { oauth_query: signed.query, accept: false }, selection);
      const redirectUrl = await validatedProviderRedirect(providerResponse, new URL(flow.redirectUri).origin, new URL(flow.redirectUri).pathname);
      const callback = new URL(redirectUrl);
      const errors = callback.searchParams.getAll("error");
      const states = callback.searchParams.getAll("state");
      const issuers = callback.searchParams.getAll("iss");
      const descriptions = callback.searchParams.getAll("error_description");
      if (errors.length !== 1 || errors[0] !== "access_denied" || states.length !== 1 || states[0] !== signed.state ||
        descriptions.length !== 1 || descriptions[0] !== "User denied access" ||
        (issuers.length > 0 && (issuers.length !== 1 || issuers[0] !== `${dependencies.config.publicOrigin}/api/auth`)) ||
        [...callback.searchParams.keys()].some((key) => !["error", "error_description", "state", "iss"].includes(key))) {
        throw new HttpError(502, "OAUTH_CALLBACK_INVALID", "The OAuth provider returned an invalid denial callback");
      }
      return reply.header("Cache-Control", "no-store").send({ redirectUrl });
    }
    const providerResponse = await callOAuthProvider(request, dependencies, "consent", { oauth_query: signed.query, accept: true }, selection);
    const redirectUrl = await validatedProviderRedirect(providerResponse, new URL(flow.redirectUri).origin, new URL(flow.redirectUri).pathname);
    const callback = new URL(redirectUrl);
    const codes = callback.searchParams.getAll("code");
    const states = callback.searchParams.getAll("state");
    const issuers = callback.searchParams.getAll("iss");
    if (codes.length !== 1 || !codes[0] || states.length !== 1 || states[0] !== signed.state ||
      (issuers.length > 0 && (issuers.length !== 1 || issuers[0] !== `${dependencies.config.publicOrigin}/api/auth`)) ||
      [...callback.searchParams.keys()].some((key) => !["code", "state", "iss"].includes(key))) {
      throw new HttpError(502, "OAUTH_CALLBACK_INVALID", "The OAuth provider returned a callback with unexpected parameters");
    }
    const authorizationCodeHash = createHash("sha256").update(codes[0]!).digest("base64url");
    const boundCode = await dependencies.db.update(agentOauthAuthorizations).set({ authorizationCodeHash })
      .where(and(eq(agentOauthAuthorizations.id, flow.id), eq(agentOauthAuthorizations.status, "approved"), isNull(agentOauthAuthorizations.authorizationCodeHash)))
      .returning({ id: agentOauthAuthorizations.id });
    if (boundCode.length !== 1) throw new HttpError(409, "OAUTH_CODE_ALREADY_BOUND", "The OAuth authorization code is already bound to another flow");
    return reply.header("Cache-Control", "no-store").send({ redirectUrl });
  });

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
    const match = typeof authorization === "string" ? /^Bearer ([^\s]{1,8192})$/.exec(authorization) : null;
    if (!match) throw new HttpError(401, "UNAUTHORIZED", "A valid agent bearer credential is required");
    const principal = await resolveAgentPrincipal(dependencies, match[1]!);
    if (!principal) throw new HttpError(401, "UNAUTHORIZED", "The agent bearer credential is expired or revoked");
    await dependencies.rateLimit(request, `agent-preflight-${principal.credentialId}`, dependencies.preflightRateLimitMax);

    const requestedAgent = request.headers["x-agent-id"];
    const requestedResource = request.headers["x-agent-resource"];
    if (typeof requestedAgent !== "string" || requestedAgent !== principal.agentId ||
      principal.resource !== dependencies.agentResource ||
      typeof requestedResource !== "string" || requestedResource !== principal.resource) {
      throw new HttpError(403, "FORBIDDEN", "The credential is not bound to the requested agent and resource");
    }
    return reply.header("Cache-Control", "no-store").send({
      allowed: true,
      agentId: principal.agentId,
      resource: principal.resource,
      role: principal.role,
      accessRevision: principal.accessRevision,
      accessGeneration: principal.accessGeneration,
      policyRevision: principal.policyRevision,
      permissions: principal.permissions
    });
  });
}
