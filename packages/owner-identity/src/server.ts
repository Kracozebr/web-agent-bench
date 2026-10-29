import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import multipart from "@fastify/multipart";
import { resolve } from "node:path";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import { getAddress, verifyMessage } from "viem";
import { allowedAgentRequestHosts, registerAgentRoutes, resolveAgentPrincipal, type AgentRouteDependencies } from "./agents.js";
import { registerLedgerRoutes } from "./ledger.js";
import { registerBonusCodeRoutes } from "./bonus-code-routes.js";
import { registerBetaOperationsRoutes } from "./beta-operations-routes.js";
import { registerBetaUsageSupportRoutes } from "./beta-usage-support-routes.js";
import { pinnedBetaClientRegistryFromManifest } from "./beta-usage-support-export.js";
import { registerSupportReportRoutes } from "./report-routes.js";
import { registerSupportReportMcpTools } from "./report-mcp.js";
import { createReportClosureStateStore } from "./report-closure-state.js";
import { runReportHousekeeping, runReportRetentionCleanup, type ReportServiceDependencies } from "./report-service.js";
import { REPORT_IMAGE_MAX_INPUT_BYTES } from "./report-images.js";
import { registerRunIntentMcpTools, registerRunRoutes } from "./run-routes.js";
import { consumeRunCancellationOutbox, expireQueuedRuns } from "./run-service.js";
import type { RunServiceDependencies } from "./run-service.js";
import { unavailableTaskExecutionReadinessProvider, type TaskExecutionReadiness } from "./task-release.js";
import { registerPublicRankedRoutes } from "./public-ranked.js";
import { createPostgresTaskReleaseProvider, createPostgresTaskReleaseQuerySource } from "./task-store.js";
import { closeExpiredTaskActions } from "./task-action-service.js";
import { cleanupFailedLocalBefTaskCoordinatorStartup, createLocalBefTaskCoordinator,
  createBetaBefTaskCoordinator, BETA_BEF_RUN_SERVICE_POLICY, LOCAL_BEF_RUN_SERVICE_POLICY,
  type BetaBefTaskCoordinator, type LocalBefTaskCoordinator } from "./bef-task-coordinator.js";
import { pinBetaRunReleaseProvider } from "./beta-bef-runtime-profile.js";
import { createAuth, siweRequestFingerprint, withSiweRequest } from "./auth.js";
import { loadConfig, getGoogleMode } from "./config.js";
import { createDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { responseError as mapResponseError } from "./http-error-response.js";
import {
  admissions,
  authFlows,
  auditEvents,
  agentOauthAuthorizations,
  authAccount,
  authUser,
  identities,
  invitationRedemptions,
  invitations,
  googleLinkStates,
  owners,
  rateLimits,
  registrationPolicy,
  siweChallenges,
  authWalletAddress
} from "./schema.js";

const config = loadConfig();
const { db, client } = createDatabase(config);
const auth = createAuth(config, db);
const app = Fastify({ logger: false, trustProxy: false, bodyLimit: 64 * 1024 });
const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const hmac = (value: string) => createHmac("sha256", config.authSecret).update(value).digest("hex");
const randomToken = () => randomBytes(32).toString("base64url");
let startupCoordinatorForCleanup: LocalBefTaskCoordinator | undefined;

interface Authenticated {
  user: { id: string; email: string; name: string };
  session: { id: string; expiresAt: Date };
}
interface IdentityView { provider: string; subject: string; verifiedAt: Date }
interface OwnerContext {
  owner: typeof owners.$inferSelect;
  identities: IdentityView[];
  policyRevision: number;
  isAdmin: boolean;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function operationId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(value)) {
    throw new HttpError(400, "INVALID_OPERATION_ID", "operationId must be a 12-128 character idempotency key");
  }
  return value;
}

function normalizeProvider(providerId: string): string | undefined {
  const provider = providerId.toLowerCase();
  if (provider === "google") return "google";
  if (provider === "siwe" || provider === "wallet" || provider === "ethereum") return "wallet";
  return undefined;
}

function adminProviderName(provider: string): string {
  return normalizeProvider(provider) ?? provider;
}

function responseError(reply: FastifyReply, error: unknown) {
  return mapResponseError(reply, error, requestSafeLog);
}

function requestSafeLog(error: unknown) {
  const kind = error instanceof Error ? error.name : "UnknownError";
  app.log.error({ kind }, "owner-identity request failed");
}

function headersFrom(request: FastifyRequest): Headers {
  const result = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) result.set(key, value.join(", "));
    else result.set(key, String(value));
  }
  return result;
}

async function authenticated(request: FastifyRequest): Promise<Authenticated> {
  const result = await auth.api.getSession({ headers: headersFrom(request) });
  if (!result) throw new HttpError(401, "UNAUTHORIZED", "An authenticated session is required");
  return result as unknown as Authenticated;
}

async function recordAudit(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  eventType: string,
  opId: string,
  options: {
    actorOwnerId?: string | null;
    subjectOwnerId?: string | null;
    invitationId?: string | null;
    policyRevision?: number | null;
    metadata?: Record<string, unknown>;
  } = {}
) {
  await tx.insert(auditEvents).values({
    id: randomUUID(), eventType, operationId: opId,
    actorOwnerId: options.actorOwnerId ?? null,
    subjectOwnerId: options.subjectOwnerId ?? null,
    invitationId: options.invitationId ?? null,
    policyRevision: options.policyRevision ?? null,
    metadata: options.metadata ?? {},
    createdAt: new Date()
  });
}

async function completeAuthFlow(flow: typeof authFlows.$inferSelect, success: boolean, reason?: string) {
  await db.transaction(async (tx) => {
    const completedAt = new Date();
    const changed = await tx.update(authFlows).set({ completedAt, outcome: success ? "succeeded" : "failed" })
      .where(and(eq(authFlows.id, flow.id), isNull(authFlows.completedAt)))
      .returning({ operationId: authFlows.operationId });
    if (changed.length !== 1) return;
    const eventType = flow.purpose === "signin"
      ? (success ? "auth.session_succeeded" : "auth.session_failed")
      : (success ? "auth.identity_link_succeeded" : "auth.identity_link_failed");
    await recordAudit(tx, eventType, flow.operationId, {
      actorOwnerId: flow.ownerId,
      subjectOwnerId: flow.ownerId,
      metadata: {
        provider: flow.provider,
        purpose: flow.purpose,
        ...(reason ? { reason } : {})
      }
    });
  });
}

async function auditAuthFlowFailure(flow: typeof authFlows.$inferSelect, reason: string) {
  await db.transaction(async (tx) => {
    await tx.update(authFlows).set({ outcome: "failed" }).where(and(eq(authFlows.id, flow.id), isNull(authFlows.completedAt)));
    await recordAudit(tx, flow.purpose === "signin" ? "auth.session_failed" : "auth.identity_link_failed", flow.operationId, {
      actorOwnerId: flow.ownerId, subjectOwnerId: flow.ownerId,
      metadata: { provider: flow.provider, purpose: flow.purpose, reason }
    });
  });
}

async function auditSiweOutcome(opId: string, success: boolean, reason?: string) {
  await db.transaction(async (tx) => {
    await recordAudit(tx, success ? "auth.session_succeeded" : "auth.session_failed", opId, {
      metadata: { provider: "wallet", purpose: "signin", ...(reason ? { reason } : {}) }
    });
  });
}

async function auditOAuthCodeExchange(request: FastifyRequest, response: Response): Promise<Response> {
  const code = asRecord(request.body).code;
  if (typeof code !== "string" || code.length < 1 || code.length > 512) return response;
  const authorizationCodeHash = createHash("sha256").update(code).digest("base64url");
  const authorization = await db.query.agentOauthAuthorizations.findFirst({
    where: eq(agentOauthAuthorizations.authorizationCodeHash, authorizationCodeHash)
  });
  if (!authorization) return response;

  let tokenValid = false;
  if (response.ok) {
    try {
      const responseBody = asRecord(await response.clone().json());
      const accessToken = responseBody.access_token;
      if (typeof accessToken === "string" && accessToken.length <= 8192) {
        const verified = await auth.api.verifyJWT({ body: { token: accessToken, issuer: `${config.publicOrigin}/api/auth` } });
        const claims = asRecord(verified.payload);
        const audience = claims.aud;
        const resourceMatches = audience === authorization.resource ||
          (Array.isArray(audience) && audience.length === 1 && audience[0] === authorization.resource);
        tokenValid = Boolean(verified.payload && resourceMatches && claims.iss === `${config.publicOrigin}/api/auth` &&
          claims.sub === authorization.authUserId && claims.azp === authorization.clientId && claims.scope === "agent:operate" &&
          claims.oid_owner_id === authorization.ownerId && claims.oid_agent_id === authorization.agentId &&
          claims.oid_grant_id === authorization.grantId && claims.oid_access_generation === authorization.accessGeneration &&
          claims.oid_role === "agent");
      }
    } catch {
      tokenValid = false;
    }
  }

  if (response.ok && !tokenValid) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 502,
      headers: { "content-type": "application/json", "cache-control": "no-store" }
    });
  }

  const eventType = tokenValid ? "agent.oauth.code_exchanged" : "agent.oauth.code_exchange_rejected";
  const eventOperationId = tokenValid ? `oauth-exchange:${authorization.id}` : `oauth-exchange-rejected:${authorization.id}:${randomUUID()}`;
  await db.transaction(async (tx) => {
    const current = await tx.query.agentOauthAuthorizations.findFirst({
      where: eq(agentOauthAuthorizations.id, authorization.id)
    });
    if (!current || current.status !== "approved" || current.authorizationCodeHash !== authorizationCodeHash) return;
    const existing = tokenValid ? await tx.query.auditEvents.findFirst({
      where: and(eq(auditEvents.eventType, eventType), eq(auditEvents.operationId, eventOperationId))
    }) : undefined;
    if (existing) return;
    await tx.insert(auditEvents).values({
      id: randomUUID(), eventType, operationId: eventOperationId,
      actorOwnerId: current.ownerId, subjectOwnerId: current.ownerId,
      invitationId: null, policyRevision: current.policyRevision,
      metadata: {
        authorizationId: current.id,
        agentId: current.agentId,
        grantId: current.grantId,
        clientId: current.clientId,
        resource: current.resource
      },
      createdAt: new Date()
    });
  });
  return response;
}

async function sessionFromAuthResponse(response: Response): Promise<Authenticated | null> {
  const cookies = response.headers.getSetCookie().flatMap((cookieValue) => {
    const pair = cookieValue.split(";", 1)[0];
    return pair ? [pair] : [];
  });
  if (!cookies.some((cookieValue) => cookieValue.toLowerCase().includes("session_token="))) return null;
  const headers = new Headers({ cookie: cookies.join("; "), origin: config.publicOrigin });
  const result = await auth.api.getSession({ headers });
  return result ? result as unknown as Authenticated : null;
}

async function ensureOwner(session: Authenticated): Promise<OwnerContext> {
  const user = await db.query.authUser.findFirst({ where: eq(authUser.id, session.user.id) });
  if (!user) throw new HttpError(401, "UNAUTHORIZED", "Authenticated user was not found");
  const accounts = await db.query.authAccount.findMany({ where: eq(authAccount.userId, user.id) });
  const mapped = accounts.flatMap((account) => {
    const provider = normalizeProvider(account.providerId);
    if (!provider) return [];
    const subject = provider === "wallet" ? account.accountId.split(":")[0]!.toLowerCase() : account.accountId;
    return [{ provider, subject }];
  });
  const existing = await db.query.owners.findFirst({ where: eq(owners.authUserId, user.id) });
  let ownerId = existing?.id;

  await db.transaction(async (tx) => {
    let owner = await tx.query.owners.findFirst({ where: eq(owners.authUserId, user.id) });
    if (!owner) {
      const policyRows = await tx.execute(sql`SELECT mode,revision FROM oid_registration_policy WHERE id=1 FOR UPDATE`);
      const policy = policyRows[0] as { mode: string; revision: number } | undefined;
      const revision = policy?.revision ?? 1;
      const adminMatch = mapped.some((identity) =>
        config.adminProvider && config.adminSubject &&
        identity.provider === adminProviderName(config.adminProvider) && identity.subject === config.adminSubject
      );
      const admitted = policy?.mode === "open" || adminMatch;
      const now = new Date();
      const inserted = await tx.insert(owners).values({
        id: randomUUID(), authUserId: user.id,
        admissionStatus: admitted ? "admitted" : "pending",
        createdAt: now, admittedAt: admitted ? now : null
      }).onConflictDoNothing({ target: owners.authUserId }).returning();
      owner = inserted[0] ?? await tx.query.owners.findFirst({ where: eq(owners.authUserId, user.id) });
      if (!owner) throw new Error("Owner row could not be established");
      const created = inserted.length === 1;
      ownerId = owner.id;
      if (created) {
        await recordAudit(tx, "owner.created", `owner-create:${owner.id}`, {
          subjectOwnerId: owner.id,
          policyRevision: revision,
          metadata: { admissionStatus: admitted ? "admitted" : "pending" }
        });
      }
      if (admitted && created) {
        const autoOperation = `system-admit:${owner.id}`;
        await tx.insert(admissions).values({ ownerId: owner.id, operationId: autoOperation, invitationId: null, policyRevision: revision, admittedAt: now });
        await recordAudit(tx, adminMatch ? "owner.admin_bootstrap_admitted" : "owner.open_registration_admitted", autoOperation, {
          subjectOwnerId: owner.id, policyRevision: revision
        });
      }
    }
    if (!owner) throw new Error("Owner row could not be established");
    ownerId = owner.id;
    for (const identity of mapped) {
      const insertedIdentity = await tx.insert(identities).values({
        id: randomUUID(), ownerId: owner.id, authUserId: user.id,
        provider: identity.provider, subject: identity.subject,
        verifiedAt: new Date(), createdAt: new Date()
      }).onConflictDoNothing().returning({ id: identities.id });
      const matching = await tx.query.identities.findFirst({
        where: and(eq(identities.ownerId, owner.id), eq(identities.provider, identity.provider))
      });
      if (!matching || matching.subject !== identity.subject) {
        throw new HttpError(409, "IDENTITY_ALREADY_LINKED", "This identity is already linked to another owner");
      }
      if (insertedIdentity.length === 1) {
        await recordAudit(tx, "owner.identity_linked", `identity-link:${owner.id}:${identity.provider}:${sha256(identity.subject).slice(0, 20)}`, {
          actorOwnerId: owner.id, subjectOwnerId: owner.id,
          metadata: { provider: identity.provider }
        });
      }
    }
  });

  if (!ownerId) throw new Error("Owner identity sync failed");
  const owner = await db.query.owners.findFirst({ where: eq(owners.id, ownerId) });
  if (!owner) throw new Error("Owner identity sync failed");
  const storedIdentities = await db.query.identities.findMany({ where: eq(identities.ownerId, owner.id) });
  const policy = await db.query.registrationPolicy.findFirst({ where: eq(registrationPolicy.id, 1) });
  const isAdmin = Boolean(config.adminProvider && config.adminSubject && storedIdentities.some((identity) =>
    identity.provider === adminProviderName(config.adminProvider!) && identity.subject === config.adminSubject
  ));
  return { owner, identities: storedIdentities.map(({ provider, subject, verifiedAt }) => ({ provider, subject, verifiedAt })), policyRevision: policy?.revision ?? 1, isAdmin };
}

async function ownerFor(session: Authenticated): Promise<OwnerContext> {
  const owner = await db.query.owners.findFirst({ where: eq(owners.authUserId, session.user.id) });
  if (!owner) throw new HttpError(409, "OWNER_NOT_INITIALIZED", "Verified identity is not provisioned yet");
  const storedIdentities = await db.query.identities.findMany({ where: eq(identities.ownerId, owner.id) });
  const policy = await db.query.registrationPolicy.findFirst({ where: eq(registrationPolicy.id, 1) });
  const isAdmin = Boolean(config.adminProvider && config.adminSubject && storedIdentities.some((identity) =>
    identity.provider === adminProviderName(config.adminProvider!) && identity.subject === config.adminSubject
  ));
  return { owner, identities: storedIdentities.map(({ provider, subject, verifiedAt }) => ({ provider, subject, verifiedAt })), policyRevision: policy?.revision ?? 1, isAdmin };
}

async function requireAdmin(request: FastifyRequest): Promise<{ session: Authenticated; context: OwnerContext }> {
  const session = await authenticated(request);
  const context = await ownerFor(session);
  if (!context.isAdmin) throw new HttpError(403, "FORBIDDEN", "The configured administrator identity is required");
  return { session, context };
}

async function requireOrigin(request: FastifyRequest) {
  if (request.headers.origin !== config.publicOrigin) {
    throw new HttpError(403, "FORBIDDEN", "A same-origin request is required");
  }
}

async function rateLimit(request: FastifyRequest, group: string, limit: number) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(nowSeconds / config.rateLimitWindowSeconds);
  const rateKey = hmac(`${group}\n${request.ip}`);
  const rows = await db.insert(rateLimits).values({ keyHash: rateKey, bucketStart: bucket, requestCount: 1, updatedAt: new Date() })
    .onConflictDoUpdate({
      target: rateLimits.keyHash,
      set: {
        bucketStart: bucket,
        requestCount: sql`CASE WHEN ${rateLimits.bucketStart} = ${bucket} THEN ${rateLimits.requestCount} + 1 ELSE 1 END`,
        updatedAt: new Date()
      }
    }).returning({ requestCount: rateLimits.requestCount });
  if ((rows[0]?.requestCount ?? limit + 1) > limit) {
    throw new HttpError(429, "RATE_LIMITED", "Request rate limit exceeded");
  }
  if (bucket % 16 === 0) await db.delete(rateLimits).where(lt(rateLimits.bucketStart, bucket - 2));
}

function statusOfInvitation(invite: typeof invitations.$inferSelect, now = new Date()) {
  if (invite.revokedAt) return "revoked";
  if (invite.redeemedAt) return "redeemed";
  if (invite.expiresAt <= now) return "expired";
  return "issued";
}

function identityError(message = "This identity is already linked to another owner") {
  return new HttpError(409, "IDENTITY_ALREADY_LINKED", message);
}

function parseSiwe(message: string) {
  const domain = /^([^\s]+) wants you to sign in with your Ethereum account:$/m.exec(message)?.[1];
  const address = message.split("\n").find((line) => /^0x[\da-fA-F]{40}$/.test(line));
  const uri = /^URI:\s*(\S+)\s*$/m.exec(message)?.[1];
  const version = /^Version:\s*(\S+)\s*$/m.exec(message)?.[1];
  const chainIdRaw = /^Chain ID:\s*(\d+)\s*$/m.exec(message)?.[1];
  const nonce = /^Nonce:\s*([a-zA-Z0-9]{8,250})\s*$/m.exec(message)?.[1];
  const issuedAtRaw = /^Issued At:\s*(\S+)\s*$/m.exec(message)?.[1];
  const expirationRaw = /^Expiration Time:\s*(\S+)\s*$/m.exec(message)?.[1];
  const notBeforeRaw = /^Not Before:\s*(\S+)\s*$/m.exec(message)?.[1];
  const statement = /Ethereum account:\n[^\n]+\n\n([^\n]+)/m.exec(message)?.[1];
  const issuedAt = issuedAtRaw ? new Date(issuedAtRaw) : undefined;
  const expiration = expirationRaw ? new Date(expirationRaw) : undefined;
  const notBefore = notBeforeRaw ? new Date(notBeforeRaw) : undefined;
  if (!domain || !address || !uri || version !== "1" || !chainIdRaw || !nonce || !issuedAt || Number.isNaN(issuedAt.getTime()) ||
    (expirationRaw !== undefined && (!expiration || Number.isNaN(expiration.getTime()))) ||
    (notBeforeRaw !== undefined && (!notBefore || Number.isNaN(notBefore.getTime())))) {
    throw new HttpError(400, "SIWE_MESSAGE_INVALID", "A complete EIP-4361 message is required");
  }
  return { domain, address, uri, chainId: Number(chainIdRaw), nonce, issuedAt, expiration, notBefore, statement };
}

async function start() {
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (request, body, done) => {
    try {
      const parsed: Record<string, string | string[]> = Object.create(null) as Record<string, string | string[]>;
      const bodyText = typeof body === "string" ? body : body.toString("utf8");
      for (const [key, value] of new URLSearchParams(bodyText)) {
        const prior = parsed[key];
        if (prior === undefined) parsed[key] = value;
        else if (Array.isArray(prior)) prior.push(value);
        else parsed[key] = [prior, value];
      }
      done(null, parsed);
    } catch (error) {
      done(error as Error);
    }
  });
  await app.register(cookie);
  await app.register(multipart, { limits: { fieldNameSize: 32, fieldSize: 128, fields: 4, files: 1,
    fileSize: REPORT_IMAGE_MAX_INPUT_BYTES, headerPairs: 16, parts: 5 }, throwFileSizeLimit: false });
  app.addHook("onRequest", async (request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Cache-Control", "no-store");
    const pathname = new URL(request.url, config.publicOrigin).pathname;
    // AICODE-NOTE: Remote agent HTTP acceptance has no browser Origin header; its route authenticates the bearer principal and rejects a mismatched optional Origin.
    const isAgentRunAcceptance = /^\/api\/agent\/run-intents\/[0-9a-f-]{36}\/accept$/i.test(pathname);
    const isAgentTaskOperation = /^\/api\/agent\/runs\/[0-9a-f-]{36}\/tasks\/(?:[0-9]|1[01])\/(?:actions|finish)$/i.test(pathname);
    const isAgentSupportReportMutation = request.method === "POST" &&
      /^\/api\/agent\/(?:reports|report-images\/uploads|report-images\/uploads\/[0-9a-f-]{36}\/(?:chunks|finish))$/i.test(pathname);
    if (pathname.startsWith("/api/") && request.method !== "GET" && request.method !== "HEAD" &&
      !pathname.startsWith("/api/auth/") && pathname !== "/api/agent/mcp" && !isAgentRunAcceptance &&
      !isAgentTaskOperation && !isAgentSupportReportMutation) {
      try { await requireOrigin(request); }
      catch (error) { return responseError(reply, error); }
    }
  });

  const taskReleaseSource = createPostgresTaskReleaseQuerySource(db);
  let localBefTaskCoordinator: LocalBefTaskCoordinator | undefined;
  let betaBefTaskCoordinator: LocalBefTaskCoordinator | undefined;
  if (config.betaManifest) {
    betaBefTaskCoordinator = await createBetaBefTaskCoordinator({ db, databaseUrl: config.databaseUrl,
      config, releaseSource: taskReleaseSource });
    startupCoordinatorForCleanup = betaBefTaskCoordinator;
    await betaBefTaskCoordinator.acquire();
  } else if (config.localBefTaskCoordinatorEnabled) {
    localBefTaskCoordinator = await createLocalBefTaskCoordinator({
      db,
      databaseUrl: config.databaseUrl,
      config,
      releaseSource: taskReleaseSource,
    });
    startupCoordinatorForCleanup = localBefTaskCoordinator;
    await localBefTaskCoordinator.acquire();
  }
  // Durable pause and operations controls are available to an explicitly manifested Beta runtime
  // or a strict isolated loopback fixture; Beta release/readiness still requires its manifest.
  const betaOperationsEnabled = config.betaManifest !== undefined || config.localReportAcceptanceEnabled;
  const operationsPrivateDataDir = config.betaManifest?.storage.privateDataDir ??
    (config.localReportAcceptanceEnabled ? config.privateDataDir : undefined);
  const runServiceDependencies = {
    db,
    betaOperationsEnabled,
    ...(betaOperationsEnabled && operationsPrivateDataDir ? { privateDataDir: operationsPrivateDataDir } : {}),
    bonusOnly: config.betaManifest !== undefined,
    admissionReleaseProvider: config.betaManifest
      ? pinBetaRunReleaseProvider(createPostgresTaskReleaseProvider(db), config.betaManifest)
      : createPostgresTaskReleaseProvider(db),
    taskReleaseSource,
    executionReadinessProvider: betaBefTaskCoordinator?.readinessProvider ?? unavailableTaskExecutionReadinessProvider,
    ...(config.betaManifest ? BETA_BEF_RUN_SERVICE_POLICY : {}),
    ...(config.localBefTaskCoordinatorEnabled ? LOCAL_BEF_RUN_SERVICE_POLICY : {})
  } satisfies RunServiceDependencies & { taskReleaseSource: ReturnType<typeof createPostgresTaskReleaseQuerySource> };
  let reportServiceDependencies: ReportServiceDependencies | undefined;
  if (config.betaManifest || config.localReportAcceptanceEnabled) {
    if (!config.privateDataDir || !config.betaReportClosureStateFile) throw new Error("report_closure_state_path_missing");
    reportServiceDependencies = {
      db,
      privateDataDir: resolve(config.privateDataDir),
      reportClosureState: createReportClosureStateStore(config.betaReportClosureStateFile)
    };
  }
  const agentRouteDependencies: AgentRouteDependencies = {
    db,
    auth,
    config,
    requireOrigin,
    rateLimit,
    rateLimitMax: config.authRateLimitMax,
    credentialRateLimitMax: config.agentCredentialRateLimitMax,
    preflightRateLimitMax: config.agentPreflightRateLimitMax,
    manualCredentialTtlSeconds: config.manualCredentialTtlSeconds,
    agentResource: `${config.publicOrigin}/api/agent`,
    agentPreflightUrl: `${config.publicOrigin}/api/agent/preflight`,
    registerMcpTools: (server, principal) => {
      registerRunIntentMcpTools(server, principal, runServiceDependencies);
      if (reportServiceDependencies) registerSupportReportMcpTools(server, principal, reportServiceDependencies);
    },
    resolveOwner: async (request) => {
      const session = await authenticated(request);
      const context = await ownerFor(session);
      return { owner: context.owner };
    }
  };
  registerAgentRoutes(app, agentRouteDependencies);

  registerRunRoutes(app, {
    ...runServiceDependencies,
    publicOrigin: config.publicOrigin,
    agentRequestHosts: allowedAgentRequestHosts(config),
    agentRateLimitMax: config.agentPreflightRateLimitMax,
    resolveOwner: async (request) => {
      const session = await authenticated(request);
      const context = await ownerFor(session);
      return { owner: context.owner };
    },
    resolveAgentPrincipal: (bearer) => resolveAgentPrincipal(agentRouteDependencies, bearer),
    requireOrigin,
    rateLimit,
    rateLimitMax: config.authRateLimitMax
  });

  registerLedgerRoutes(app, {
    db,
    requireAdmin,
    requireOrigin,
    rateLimit,
    rateLimitMax: config.authRateLimitMax,
    resolveOwner: async (request) => ownerFor(await authenticated(request))
  });

  registerBonusCodeRoutes(app, {
    db,
    ...(config.codeVerifierSecret ? { codeVerifierSecret: config.codeVerifierSecret } : {}),
    requireAdmin,
    requireOrigin,
    rateLimit,
    rateLimitMax: config.authRateLimitMax,
    resolveOwner: async (request) => {
      const context = await ownerFor(await authenticated(request));
      return { owner: context.owner };
    }
  });

  if (reportServiceDependencies) {
    registerSupportReportRoutes(app, {
      db, service: reportServiceDependencies, publicOrigin: config.publicOrigin,
      agentRequestHosts: allowedAgentRequestHosts(config), rateLimitMax: config.authRateLimitMax,
      agentRateLimitMax: config.agentPreflightRateLimitMax, imageChunkRateLimitMax: 300,
      resolveOwner: async (request) => {
        const context = await ownerFor(await authenticated(request));
        return { owner: context.owner };
      },
      resolveAgentPrincipal: (bearer) => resolveAgentPrincipal(agentRouteDependencies, bearer),
      requireAdmin, requireOrigin, rateLimit
    });
  }

  if (betaOperationsEnabled) {
    registerBetaOperationsRoutes(app, {
      db,
      ...(operationsPrivateDataDir ? { privateDataDir: operationsPrivateDataDir } : {}),
      workerLease: () => {
        const coordinator = betaBefTaskCoordinator ?? localBefTaskCoordinator;
        return coordinator ? coordinator.ownsLease() : null;
      },
      runtimeHealth: async () => {
        if (!config.betaManifest) return 'not_configured';
        const provider = (betaBefTaskCoordinator as BetaBefTaskCoordinator | undefined)?.readinessProvider;
        if (!provider) return 'unavailable';
        const ready = await provider.isRuntimeHealthyForRelease(config.betaManifest.release.releaseIdentity,
          config.betaManifest.release.manifestHash).catch(() => false);
        return ready ? 'ready' : 'unavailable';
      },
      environmentCapacity: async () => {
        if (!config.betaManifest) return 'not_configured';
        const provider = (betaBefTaskCoordinator as BetaBefTaskCoordinator | undefined)?.readinessProvider;
        if (!provider) return 'unavailable';
        const result = await provider.isPreparedForRelease(config.betaManifest.release.releaseIdentity,
          config.betaManifest.release.manifestHash).catch((): TaskExecutionReadiness => ({ ready: false }));
        return result.ready && typeof result.environmentId === 'string' && /^[0-9a-f]{64}$/.test(result.evidenceHash ?? '')
          ? 'ready' : 'unavailable';
      },
      requireAdmin, requireOrigin, rateLimit, rateLimitMax: config.authRateLimitMax,
    });
    registerBetaUsageSupportRoutes(app, {
      db,
      ...(config.betaManifest ? { clientRegistry: pinnedBetaClientRegistryFromManifest(config.betaManifest) } : {}),
      requireAdmin,
      rateLimit,
      rateLimitMax: config.authRateLimitMax,
    });
  }

  // AICODE-NOTE: Public qualification reads use only request.raw.socket.remoteAddress. Fastify trustProxy stays false; a shared proxy cannot enforce an end-user allowlist.
  registerPublicRankedRoutes(app, { db, config });

  app.get("/healthz", async (_request, reply) => {
    await db.execute(sql`SELECT 1`);
    return reply.send({ status: "ok" });
  });

  app.get("/readyz", async (_request, reply) => {
    try {
      await db.execute(sql`SELECT 1`);
      return reply.send({ status: "ready" });
    } catch {
      return reply.code(503).send({ status: "not_ready" });
    }
  });

  app.get("/api/identity/config", async (_request, reply) => reply.send({
    googleEnabled: getGoogleMode(config) !== "disabled",
    googleMode: getGoogleMode(config),
    siwe: {
      enabled: !config.betaManifest,
      domain: new URL(config.publicOrigin).host,
      uri: config.publicOrigin,
      chainId: config.siweChainId,
      statement: "Sign in to Web3 Agent Bench",
      nonceTtlSeconds: config.nonceTtlSeconds
    }
  }));

  app.get("/api/identity/connection-profile", async (_request, reply) => reply.send({
    protocolVersion: config.betaManifest ? undefined : "2026-07-28",
    protocolVersions: config.betaManifest ? [...new Set(config.betaManifest.clients.filter((profile) => profile.enabled)
      .flatMap((profile) => profile.protocolVersions))] : ["2026-07-28"],
    serverUrl: `${config.publicOrigin}/api/agent/mcp`,
    resource: `${config.publicOrigin}/api/agent`,
    issuer: `${config.publicOrigin}/api/auth`,
    clientId: config.betaManifest ? (config.mcpClientRegistry?.length === 1 ? config.mcpClientRegistry[0]?.clientId ?? null : null) : config.mcpClientId,
    redirectUri: config.betaManifest ? (config.mcpClientRegistry?.length === 1 ? config.mcpClientRegistry[0]?.redirectUris[0] ?? null : null) : config.mcpClientRedirectUri,
    clientRegistrations: (config.mcpClientRegistry ?? []).map(({ clientId, redirectUris, clientName }) => ({ clientId, redirectUris, clientName })),
    clientProfiles: config.betaManifest?.clients.filter((profile) => profile.enabled).map((profile) => ({
      family: profile.family, edition: profile.edition, version: profile.version, platform: profile.platform,
      mcpClientName: profile.mcpClientName, mcpClientVersion: profile.mcpClientVersion,
      protocolVersions: profile.protocolVersions, authMethods: profile.authMethods
    })) ?? [],
    registration: config.betaManifest ? (config.mcpClientRegistry?.length ? "pre-registered" : "manual-bearer-only") : "pre-registered",
    authorizationEndpointUrl: `${config.publicOrigin}/api/auth/oauth2/authorize`,
    tokenEndpointUrl: `${config.publicOrigin}/api/auth/oauth2/token`,
    authorizationServerMetadataUrl: `${config.publicOrigin}/.well-known/oauth-authorization-server/api/auth`,
    protectedResourceMetadataUrl: `${config.publicOrigin}/.well-known/oauth-protected-resource/api/agent`
  }));

  app.get("/.well-known/oauth-protected-resource/api/agent", async (_request, reply) => reply.send({
    resource: `${config.publicOrigin}/api/agent`,
    authorization_servers: [`${config.publicOrigin}/api/auth`],
    scopes_supported: ["agent:operate"],
    bearer_methods_supported: ["header"]
  }));

  app.get("/.well-known/oauth-authorization-server/api/auth", async (request, reply) => {
    const metadata = await auth.api.getOAuthServerConfig({
      request: new Request(new URL(request.url, config.publicOrigin)),
      asResponse: false
    });
    return reply.header("Cache-Control", "public, max-age=15").send(metadata);
  });

  app.all("/api/auth/*", async (request, reply) => {
    const group = request.url.includes("/siwe/") ? "auth-siwe" : "auth";
    const authEndpoint = new URL(request.url, config.publicOrigin).pathname;
    if (config.betaManifest && authEndpoint.startsWith("/api/auth/siwe/")) {
      return responseError(reply, new HttpError(403, "SIGN_IN_METHOD_DISABLED", "Wallet sign-in is disabled for the beta profile"));
    }
    let flow: typeof authFlows.$inferSelect | undefined;
    let callbackSession: Authenticated | undefined;
    let contextCookie: string | undefined;
    let expireFlowCookie = false;
    let siweContextCookie: string | undefined;
    let expireSiweCookie = false;
    let siweContextHash: string | undefined;
    let siweOperationId: string | undefined;
    let authFlowResult: Response | undefined;
    let preserveFlowOnError = false;
    let signOutFlows: (typeof authFlows.$inferSelect)[] = [];
    let signOutChallenges: (typeof siweChallenges.$inferSelect)[] = [];
    try {
      await rateLimit(request, group, group === "auth-siwe" ? config.siweRateLimitMax : config.authRateLimitMax);
      const endpoint = new URL(request.url, config.publicOrigin).pathname;
      const method = request.method.toUpperCase();
      const allowedMethods: Record<string, string[]> = {
        "/api/auth/sign-in/social": ["POST"],
        "/api/auth/link-social": ["POST"],
        "/api/auth/callback/google": ["GET"],
        "/api/auth/siwe/nonce": ["POST"],
        "/api/auth/siwe/get-nonce": ["POST"],
        "/api/auth/siwe/verify": ["POST"],
        "/api/auth/get-session": ["GET"],
        "/api/auth/sign-out": ["POST"],
        "/api/auth/error": ["GET"],
        "/api/auth/.well-known/oauth-authorization-server": ["GET"],
        "/api/auth/jwks": ["GET"],
        "/api/auth/oauth2/authorize": ["GET", "POST"],
        "/api/auth/oauth2/continue": ["POST"],
        "/api/auth/oauth2/consent": ["POST"],
        "/api/auth/oauth2/token": ["POST"]
      };
      if (!allowedMethods[endpoint]?.includes(method)) throw new HttpError(404, "NOT_FOUND", "Authentication endpoint is not enabled");
      const isSiwe = endpoint.startsWith("/api/auth/siwe/");
      if (endpoint === "/api/auth/siwe/nonce" || endpoint === "/api/auth/siwe/get-nonce") {
        const contextSecret = randomToken();
        const secure = config.nodeEnv === "production" ? "; Secure" : "";
        siweContextCookie = `oid_siwe_context=${contextSecret}; Path=/api/auth/siwe; HttpOnly; SameSite=Lax; Max-Age=${config.nonceTtlSeconds}${secure}`;
        siweContextHash = hmac(`siwe-context:${contextSecret}`);
      } else if (endpoint === "/api/auth/siwe/verify") {
        const contextSecret = request.cookies.oid_siwe_context;
        const message = asRecord(request.body).message;
        const nonce = typeof message === "string" ? /^Nonce:\s*([a-zA-Z0-9]{8,250})\s*$/m.exec(message)?.[1] : undefined;
        if (nonce) {
          const challenge = await db.query.siweChallenges.findFirst({ where: and(eq(siweChallenges.nonceHash, sha256(nonce)), eq(siweChallenges.purpose, "signin")) });
          siweOperationId = challenge?.operationId;
        }
        if (!contextSecret) throw new HttpError(401, "SIWE_CONTEXT_MISSING", "Start SIWE sign-in in this browser before verifying");
        siweContextHash = hmac(`siwe-context:${contextSecret}`);
        expireSiweCookie = true;
      }

      if (endpoint === "/api/auth/sign-out") {
        const currentSession = await authenticated(request).catch(() => undefined);
        if (currentSession) {
          signOutFlows = await db.query.authFlows.findMany({ where: and(
            eq(authFlows.authSessionId, currentSession.session.id), eq(authFlows.purpose, "link"), isNull(authFlows.completedAt)
          ) });
          signOutChallenges = await db.query.siweChallenges.findMany({ where: and(
            eq(siweChallenges.authSessionId, currentSession.session.id), eq(siweChallenges.purpose, "link"), isNull(siweChallenges.consumedAt)
          ) });
        }
      }

      const bodyRecord = asRecord(request.body);
      if (endpoint === "/api/auth/sign-in/social" || endpoint === "/api/auth/link-social") {
        if (bodyRecord.provider !== "google") throw new HttpError(400, "PROVIDER_NOT_ENABLED", "Only the configured Google provider is enabled");
        let initiatingSession: Authenticated | undefined;
        let initiatingOwner: OwnerContext | undefined;
        const purpose = endpoint.endsWith("link-social") ? "link" : "signin";
        if (purpose === "link") {
          initiatingSession = await authenticated(request);
          initiatingOwner = await ownerFor(initiatingSession);
          if (initiatingOwner.owner.admissionStatus !== "admitted") throw new HttpError(403, "FORBIDDEN", "Admission is required before linking another identity");
          if (initiatingOwner.identities.some((identity) => identity.provider === "google")) {
            throw new HttpError(409, "IDENTITY_ALREADY_LINKED", "This owner already has a Google identity linked");
          }
        }
        const flowSecret = randomToken();
        const flowHash = hmac(`auth-flow:${flowSecret}`);
        const flowValues = () => {
          const now = new Date();
          return {
            id: randomUUID(), operationId: randomUUID(), provider: "google", purpose,
            ownerId: initiatingOwner?.owner.id ?? null,
            authSessionId: initiatingSession?.session.id ?? null,
            attemptHash: flowHash, startedAt: now,
            expiresAt: new Date(now.getTime() + config.nonceTtlSeconds * 1000),
            completedAt: null, outcome: null
          };
        };
        const inserted = purpose === "link" && initiatingOwner
          ? await db.transaction(async (tx) => {
            // AICODE-NOTE: Serialize link starts per owner. Better Auth permits more than one
            // provider account on a user, while oid_identity permits only one
            // subject per provider and owner. Without this lock, concurrent
            // starts can both pass the identity check and leave a partial
            // Better Auth account binding when the second callback is rejected.
            const ownerRows = await tx.execute(sql`SELECT admission_status FROM oid_owner WHERE id=${initiatingOwner!.owner.id} FOR UPDATE`);
            const ownerRow = ownerRows[0] as { admission_status: string } | undefined;
            if (!ownerRow || ownerRow.admission_status !== "admitted") {
              throw new HttpError(403, "FORBIDDEN", "Admission is required before linking another identity");
            }
            const linkedGoogle = await tx.query.identities.findFirst({
              where: and(eq(identities.ownerId, initiatingOwner!.owner.id), eq(identities.provider, "google"))
            });
            if (linkedGoogle) {
              throw new HttpError(409, "IDENTITY_ALREADY_LINKED", "This owner already has a Google identity linked");
            }
            const pendingLink = await tx.query.authFlows.findFirst({ where: and(
              eq(authFlows.ownerId, initiatingOwner!.owner.id), eq(authFlows.provider, "google"),
              eq(authFlows.purpose, "link"), isNull(authFlows.completedAt), gt(authFlows.expiresAt, new Date())
            ) });
            if (pendingLink) {
              throw new HttpError(409, "IDENTITY_LINK_IN_PROGRESS", "A Google identity link is already in progress for this owner");
            }
            return tx.insert(authFlows).values(flowValues()).returning();
          })
          : await db.insert(authFlows).values(flowValues()).returning();
        flow = inserted[0];
        if (!flow) throw new Error("Could not establish provider flow audit");
        const secure = config.nodeEnv === "production" ? "; Secure" : "";
        contextCookie = `oid_auth_flow=${flowSecret}; Path=/api/auth; HttpOnly; SameSite=Lax; Max-Age=${config.nonceTtlSeconds}${secure}`;
      }

      // AICODE-NOTE: Better Auth binds OAuth linking to a user in signed state, not
      // to the current browser session. Check our durable session binding first.
      let googleLinkState: typeof googleLinkStates.$inferSelect | undefined;
      if (endpoint === "/api/auth/callback/google") {
        const flowSecret = request.cookies.oid_auth_flow;
        const currentFlowHash = flowSecret ? hmac(`auth-flow:${flowSecret}`) : undefined;
        const state = new URL(request.url, config.publicOrigin).searchParams.get("state");
        if (state) {
          googleLinkState = await db.query.googleLinkStates.findFirst({
            where: and(eq(googleLinkStates.stateHash, sha256(state)), gt(googleLinkStates.expiresAt, new Date()), isNull(googleLinkStates.consumedAt))
          });
        }
        if (googleLinkState) {
          flow = await db.query.authFlows.findFirst({ where: eq(authFlows.operationId, googleLinkState.operationId) });
          const currentSession = await authenticated(request).catch(() => undefined);
          const validBinding = Boolean(flow && currentFlowHash && flow.attemptHash === currentFlowHash &&
            flow.attemptHash === googleLinkState.flowHash && !flow.completedAt && flow.expiresAt > new Date() &&
            flow.purpose === "link" && flow.ownerId === googleLinkState.ownerId &&
            flow.authSessionId === googleLinkState.authSessionId && currentSession?.session.id === googleLinkState.authSessionId &&
            currentSession.user.id === (await db.query.owners.findFirst({ where: eq(owners.id, googleLinkState.ownerId) }))?.authUserId);
          if (!validBinding || !flow || !currentSession) {
            if (flow) await auditAuthFlowFailure(flow, "callback_session_mismatch");
            preserveFlowOnError = true;
            throw new HttpError(401, "LINK_SESSION_MISMATCH", "The Google link must finish in the session that started it");
          }
          callbackSession = currentSession;
          const ownerContext = await ownerFor(currentSession);
          if (ownerContext.owner.id !== googleLinkState.ownerId || ownerContext.owner.admissionStatus !== "admitted") {
            await completeAuthFlow(flow, false, "callback_owner_mismatch");
            throw new HttpError(403, "FORBIDDEN", "The admitted owner session is required to complete identity linking");
          }
          const consumed = await db.update(googleLinkStates).set({ consumedAt: new Date() })
            .where(and(eq(googleLinkStates.stateHash, googleLinkState.stateHash), eq(googleLinkStates.authSessionId, currentSession.session.id), isNull(googleLinkStates.consumedAt), gt(googleLinkStates.expiresAt, new Date())))
            .returning({ stateHash: googleLinkStates.stateHash });
          if (consumed.length !== 1) {
            await auditAuthFlowFailure(flow, "callback_state_replayed");
            preserveFlowOnError = true;
            throw new HttpError(409, "LINK_STATE_INVALID", "The Google link state was already used or expired");
          }
        } else {
          flow = currentFlowHash ? await db.query.authFlows.findFirst({ where: and(eq(authFlows.attemptHash, currentFlowHash), eq(authFlows.provider, "google"), isNull(authFlows.completedAt), gt(authFlows.expiresAt, new Date())) }) : undefined;
          if (!flow) throw new HttpError(401, "OAUTH_CONTEXT_MISSING", "The Google callback is not bound to a started sign-in flow");
          if (flow.purpose !== "signin") {
            await auditAuthFlowFailure(flow, "callback_state_unmatched");
            preserveFlowOnError = true;
            throw new HttpError(401, "LINK_STATE_INVALID", "The Google link state is missing or invalid");
          }
        }
        expireFlowCookie = true;
      }

      if (isSiwe && siweContextHash === undefined) throw new HttpError(401, "SIWE_CONTEXT_MISSING", "Start SIWE sign-in in this browser before verifying");
      const headers = new Headers();
      for (const [key, value] of Object.entries(request.headers)) {
        if (value === undefined || ["host", "content-length", "connection", "transfer-encoding"].includes(key.toLowerCase())) continue;
        headers.set(key, Array.isArray(value) ? value.join(", ") : String(value));
      }
      const requestMethod = request.method.toUpperCase();
      let body: string | undefined;
      if (requestMethod !== "GET" && requestMethod !== "HEAD" && request.body !== undefined) {
        const mediaType = headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
        if (mediaType === "application/x-www-form-urlencoded") {
          const params = new URLSearchParams();
          for (const [key, value] of Object.entries(asRecord(request.body))) {
            if (typeof value === "string") params.set(key, value);
            else if (Array.isArray(value)) for (const item of value) if (typeof item === "string") params.append(key, item);
          }
          body = params.toString();
        } else {
          body = JSON.stringify(request.body);
          if (!headers.has("content-type")) headers.set("content-type", "application/json");
        }
      }
      const authRequest = new Request(`${config.publicOrigin}${request.url}`, { method: requestMethod, headers, ...(body === undefined ? {} : { body }) });
      authFlowResult = isSiwe && siweContextHash
        ? await withSiweRequest({ purpose: "signin", contextHash: siweContextHash }, () => auth.handler(authRequest))
        : await auth.handler(authRequest);
      if (endpoint === "/api/auth/oauth2/token") authFlowResult = await auditOAuthCodeExchange(request, authFlowResult);

      let outputBody = Buffer.from(await authFlowResult.clone().arrayBuffer());
      let jsonBody: Record<string, unknown> | undefined;
      const contentType = authFlowResult.headers.get("content-type") ?? "";
      if (contentType.includes("application/json") && outputBody.length) {
        try { jsonBody = asRecord(JSON.parse(outputBody.toString("utf8"))); } catch { jsonBody = undefined; }
      }
      if (endpoint === "/api/auth/sign-out" && authFlowResult.status < 400 && jsonBody?.success !== false) {
        expireFlowCookie = true;
        for (const pendingFlow of signOutFlows) await auditAuthFlowFailure(pendingFlow, "session_signed_out");
        for (const challenge of signOutChallenges) {
          await db.insert(auditEvents).values({
            id: randomUUID(), eventType: "auth.identity_link_failed", operationId: challenge.operationId,
            actorOwnerId: challenge.ownerId, subjectOwnerId: challenge.ownerId,
            invitationId: null, policyRevision: null,
            metadata: { provider: "wallet", purpose: "link", reason: "session_signed_out" },
            createdAt: new Date()
          });
        }
      }
      if ((endpoint === "/api/auth/siwe/nonce" || endpoint === "/api/auth/siwe/get-nonce") && typeof jsonBody?.nonce === "string") {
        const challenge = await db.query.siweChallenges.findFirst({ where: eq(siweChallenges.nonceHash, sha256(jsonBody.nonce)) });
        if (challenge) {
          jsonBody.operationId = challenge.operationId;
          outputBody = Buffer.from(JSON.stringify(jsonBody));
        }
      }
      if (flow && (endpoint === "/api/auth/sign-in/social" || endpoint === "/api/auth/link-social")) {
        if (authFlowResult.status >= 400) await completeAuthFlow(flow, false, "provider_start_rejected");
        else if (jsonBody) {
          jsonBody.operationId = flow.operationId;
          const authorizeUrl = typeof jsonBody.url === "string" ? jsonBody.url : typeof jsonBody.redirectURL === "string" ? jsonBody.redirectURL : undefined;
          if (flow.purpose === "link") {
            const state = authorizeUrl ? new URL(authorizeUrl).searchParams.get("state") : null;
            if (!state || !flow.ownerId || !flow.authSessionId) {
              await completeAuthFlow(flow, false, "provider_state_missing");
              throw new HttpError(502, "LINK_STATE_MISSING", "The provider did not return a verifiable link state");
            }
            const now = new Date();
            await db.insert(googleLinkStates).values({
              stateHash: sha256(state), operationId: flow.operationId, ownerId: flow.ownerId,
              authSessionId: flow.authSessionId, flowHash: flow.attemptHash, createdAt: now,
              expiresAt: new Date(now.getTime() + config.nonceTtlSeconds * 1000), consumedAt: null
            });
          }
          outputBody = Buffer.from(JSON.stringify(jsonBody));
        }
      }
      if (endpoint === "/api/auth/callback/google" && flow) {
        const location = authFlowResult.headers.get("location") ?? "";
        const success = authFlowResult.status < 400 && !/[?&]error(?:=|&|$)/i.test(location);
        if (success && flow.purpose === "signin") {
          const session = await sessionFromAuthResponse(authFlowResult);
          if (!session) {
            await completeAuthFlow(flow, false, "session_cookie_missing");
          } else {
            await ensureOwner(session);
            await completeAuthFlow(flow, true);
          }
        } else if (success && flow.purpose === "link" && callbackSession) {
          try {
            await ensureOwner(callbackSession);
            await completeAuthFlow(flow, true);
          } catch {
            await completeAuthFlow(flow, false, "identity_projection_failed");
            throw identityError("The linked provider identity could not be attached to this owner");
          }
        } else {
          await completeAuthFlow(flow, false, "provider_callback_failed");
        }
      }
      if (endpoint === "/api/auth/siwe/verify" && siweOperationId) {
        let success = authFlowResult.status < 400 && jsonBody?.success === true;
        let reason = success ? undefined : "siwe_verification_failed";
        if (success) {
          const session = await sessionFromAuthResponse(authFlowResult);
          if (session) await ensureOwner(session);
          else {
            success = false;
            reason = "session_cookie_missing";
          }
        }
        await auditSiweOutcome(siweOperationId, success, reason);
      }
      reply.code(authFlowResult.status);
      if (flow) reply.header("X-OID-Operation-Id", flow.operationId);
      authFlowResult.headers.forEach((value, key) => {
        if (key.toLowerCase() !== "set-cookie" && !["content-length", "transfer-encoding"].includes(key.toLowerCase())) reply.header(key, value);
      });
      const responseCookies = authFlowResult.headers.getSetCookie();
      if (contextCookie) responseCookies.push(contextCookie);
      const secure = config.nodeEnv === "production" ? "; Secure" : "";
      if (expireFlowCookie) responseCookies.push(`oid_auth_flow=; Path=/api/auth; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
      if (siweContextCookie) responseCookies.push(siweContextCookie);
      if (expireSiweCookie) responseCookies.push(`oid_siwe_context=; Path=/api/auth/siwe; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
      if (responseCookies.length) reply.header("Set-Cookie", responseCookies);
      return reply.send(outputBody);
    } catch (error) {
      if (flow && !flow.completedAt && error instanceof HttpError && !preserveFlowOnError) await completeAuthFlow(flow, false, error.code.toLowerCase()).catch(() => undefined);
      if (siweOperationId) await auditSiweOutcome(siweOperationId, false, error instanceof HttpError ? error.code.toLowerCase() : "auth_handler_failed").catch(() => undefined);
      if (!reply.sent) return responseError(reply, error);
      requestSafeLog(error);
    }
  });

  app.get("/api/owner", async (request, reply) => {
    try {
      const session = await authenticated(request);
      const context = await ownerFor(session);
      return reply.send({
        owner: {
          id: context.owner.id,
          admissionStatus: context.owner.admissionStatus,
          isAdmin: context.isAdmin,
          identities: context.identities
        },
        admission: { status: context.owner.admissionStatus, policyRevision: context.policyRevision }
      });
    } catch (error) { return responseError(reply, error); }
  });

  app.post("/api/admission/activate", async (request, reply) => {
    try {
      await rateLimit(request, "admission", config.authRateLimitMax);
      const session = await authenticated(request);
      const context = await ownerFor(session);
      const body = asRecord(request.body);
      const opId = operationId(body.operationId);
      const provided = typeof body.invitation === "string" ? body.invitation.trim() : "";
      const outcome = await db.transaction(async (tx) => {
        const policyRows = await tx.execute(sql`SELECT mode,revision FROM oid_registration_policy WHERE id=1 FOR UPDATE`);
        const policy = policyRows[0] as { mode: string; revision: number } | undefined;
        if (!policy) throw new Error("Registration policy row is missing; run migration");
        const now = new Date();
        const prior = await tx.query.admissions.findFirst({ where: eq(admissions.ownerId, context.owner.id) });
        if (prior) {
          if (prior.operationId === opId) return { revision: prior.policyRevision, already: true };
          throw new HttpError(409, "ADMISSION_ALREADY_GRANTED", "This owner is already admitted");
        }
        let invitationId: string | null = null;
        if (policy.mode !== "open") {
          if (!provided) throw new HttpError(403, "INVITATION_INVALID", "An active invitation is required");
          const verifierHash = sha256(provided);
          const invitation = await tx.query.invitations.findFirst({ where: eq(invitations.verifierHash, verifierHash) });
          if (!invitation) throw new HttpError(403, "INVITATION_INVALID", "The invitation is invalid");
          if (invitation.revokedAt) throw new HttpError(403, "INVITATION_REVOKED", "The invitation was revoked");
          if (invitation.redeemedAt) throw new HttpError(409, "INVITATION_CONSUMED", "The invitation was already consumed");
          if (invitation.expiresAt <= now) throw new HttpError(403, "INVITATION_EXPIRED", "The invitation has expired");
          invitationId = invitation.id;
          const claimed = await tx.update(invitations).set({ redeemedAt: now })
            .where(and(eq(invitations.id, invitation.id), isNull(invitations.revokedAt), isNull(invitations.redeemedAt), sql`${invitations.expiresAt} > clock_timestamp()`))
            .returning({ id: invitations.id });
          if (claimed.length !== 1) throw new HttpError(409, "INVITATION_CONSUMED", "The invitation was already consumed");
          await tx.insert(invitationRedemptions).values({
            invitationId: invitation.id, ownerId: context.owner.id, operationId: opId,
            policyRevision: policy.revision, redeemedAt: now
          });
        }
        await tx.insert(admissions).values({ ownerId: context.owner.id, operationId: opId, invitationId, policyRevision: policy.revision, admittedAt: now });
        await tx.update(owners).set({ admissionStatus: "admitted", admittedAt: now }).where(eq(owners.id, context.owner.id));
        await recordAudit(tx, "owner.admission_activated", opId, {
          actorOwnerId: context.owner.id, subjectOwnerId: context.owner.id,
          invitationId, policyRevision: policy.revision,
          metadata: { mode: policy.mode }
        });
        return { revision: policy.revision, already: false };
      });
      return reply.send({ owner: { id: context.owner.id, admissionStatus: "admitted" }, admission: { status: "admitted", policyRevision: outcome.revision } });
    } catch (error) { return responseError(reply, error); }
  });

  app.get("/api/admin/invitations", async (request, reply) => {
    try {
      const { context } = await requireAdmin(request);
      const rows = await db.query.invitations.findMany({ where: eq(invitations.issuedByOwnerId, context.owner.id), orderBy: (table, { desc }) => [desc(table.createdAt)] });
      const now = new Date();
      return reply.send({ invitations: rows.map((invite) => ({
        id: invite.id,
        status: statusOfInvitation(invite, now),
        issuedAt: invite.createdAt,
        expiresAt: invite.expiresAt,
        revokedAt: invite.revokedAt,
        redeemedAt: invite.redeemedAt
      })) });
    } catch (error) { return responseError(reply, error); }
  });

  app.post("/api/admin/invitations", async (request, reply) => {
    try {
      await rateLimit(request, "admin-invitations", config.authRateLimitMax);
      const { context } = await requireAdmin(request);
      const body = asRecord(request.body);
      const opId = operationId(body.operationId);
      const now = new Date();
      let expiresAt = new Date(now.getTime() + config.invitationTtlSeconds * 1000);
      if (body.expiresAt !== undefined) {
        if (typeof body.expiresAt !== "string") throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be an ISO date");
        expiresAt = new Date(body.expiresAt);
        const max = now.getTime() + 30 * 24 * 60 * 60 * 1000;
        if (Number.isNaN(expiresAt.getTime()) || expiresAt <= now || expiresAt.getTime() > max) {
          throw new HttpError(400, "INVALID_EXPIRY", "expiresAt must be in the next 30 days");
        }
      }
      const secret = `oid_${randomToken()}`;
      const invitationId = randomUUID();
      await db.transaction(async (tx) => {
        const policyRows = await tx.execute(sql`SELECT revision FROM oid_registration_policy WHERE id=1 FOR UPDATE`);
        const policy = policyRows[0] as { revision: number } | undefined;
        const inserted = await tx.insert(invitations).values({
          id: invitationId, verifierHash: sha256(secret), issuedByOwnerId: context.owner.id,
          issueOperationId: opId,
          createdAt: now, expiresAt, revokedAt: null, redeemedAt: null
        }).onConflictDoNothing({ target: invitations.issueOperationId }).returning({ id: invitations.id });
        if (inserted.length !== 1) throw new HttpError(409, "INVITATION_OPERATION_REPLAYED", "The invitation operation already ran; its secret was shown only once");
        await recordAudit(tx, "invitation.issued", opId, {
          actorOwnerId: context.owner.id, invitationId, policyRevision: policy?.revision ?? null,
          metadata: { expiresAt: expiresAt.toISOString() }
        });
      });
      return reply.code(201).send({ invitation: { id: invitationId, status: "issued", expiresAt }, secret });
    } catch (error) { return responseError(reply, error); }
  });

  app.post<{ Params: { id: string } }>("/api/admin/invitations/:id/revoke", async (request, reply) => {
    try {
      await rateLimit(request, "admin-invitations", config.authRateLimitMax);
      const { context } = await requireAdmin(request);
      const opId = operationId(asRecord(request.body).operationId);
      const invitationId = request.params.id;
      const now = new Date();
      const changed = await db.transaction(async (tx) => {
        const invite = await tx.query.invitations.findFirst({ where: and(eq(invitations.id, invitationId), eq(invitations.issuedByOwnerId, context.owner.id)) });
        if (!invite) throw new HttpError(404, "INVITATION_NOT_FOUND", "Invitation was not found");
        if (invite.redeemedAt) throw new HttpError(409, "INVITATION_CONSUMED", "A redeemed invitation cannot be revoked");
        if (invite.revokedAt) return invite.revokedAt;
        const result = await tx.update(invitations).set({ revokedAt: now })
          .where(and(eq(invitations.id, invite.id), isNull(invitations.revokedAt), isNull(invitations.redeemedAt)))
          .returning({ revokedAt: invitations.revokedAt });
        if (result.length === 0) {
          const current = await tx.query.invitations.findFirst({ where: eq(invitations.id, invite.id) });
          if (current?.redeemedAt) throw new HttpError(409, "INVITATION_CONSUMED", "A redeemed invitation cannot be revoked");
          if (current?.revokedAt) return current.revokedAt;
          throw new HttpError(409, "INVITATION_STATE_CONFLICT", "Invitation state changed; refresh before retrying");
        }
        const policy = await tx.query.registrationPolicy.findFirst({ where: eq(registrationPolicy.id, 1) });
        await recordAudit(tx, "invitation.revoked", opId, {
          actorOwnerId: context.owner.id, invitationId: invite.id,
          policyRevision: policy?.revision ?? null
        });
        return result[0]!.revokedAt ?? now;
      });
      return reply.send({ invitation: { id: invitationId, status: "revoked", revokedAt: changed } });
    } catch (error) { return responseError(reply, error); }
  });

  app.get("/api/admin/registration-policy", async (request, reply) => {
    try {
      await requireAdmin(request);
      const policy = await db.query.registrationPolicy.findFirst({ where: eq(registrationPolicy.id, 1) });
      if (!policy) throw new Error("Registration policy row is missing; run migration");
      return reply.send({ mode: policy.mode, revision: policy.revision, updatedAt: policy.updatedAt });
    } catch (error) { return responseError(reply, error); }
  });

  app.put("/api/admin/registration-policy", async (request, reply) => {
    try {
      await rateLimit(request, "admin-policy", config.authRateLimitMax);
      const { context } = await requireAdmin(request);
      const body = asRecord(request.body);
      const mode = body.mode;
      if (mode !== "closed" && mode !== "open") throw new HttpError(400, "INVALID_POLICY_MODE", "mode must be closed or open");
      const expectedRevision = body.expectedRevision;
      if (typeof expectedRevision !== "number" || !Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
        throw new HttpError(400, "INVALID_POLICY_REVISION", "expectedRevision must be a positive integer");
      }
      const opId = operationId(body.operationId ?? randomUUID());
      const updatedAt = new Date();
      const result = await db.transaction(async (tx) => {
        const rows = await tx.update(registrationPolicy).set({
          mode, revision: expectedRevision + 1, updatedAt, updatedByOwnerId: context.owner.id
        }).where(and(eq(registrationPolicy.id, 1), eq(registrationPolicy.revision, expectedRevision)))
          .returning({ mode: registrationPolicy.mode, revision: registrationPolicy.revision, updatedAt: registrationPolicy.updatedAt });
        if (!rows[0]) throw new HttpError(409, "POLICY_REVISION_CONFLICT", "Registration policy changed; refresh before retrying");
        await recordAudit(tx, "registration_policy.changed", opId, {
          actorOwnerId: context.owner.id, policyRevision: rows[0].revision,
          metadata: { mode: rows[0].mode, previousRevision: expectedRevision }
        });
        return rows[0];
      });
      return reply.send(result);
    } catch (error) { return responseError(reply, error); }
  });

  app.post("/api/owner/links/siwe/nonce", async (request, reply) => {
    try {
      if (config.betaManifest) throw new HttpError(403, "SIGN_IN_METHOD_DISABLED", "Wallet identity linking is disabled for the beta profile");
      await rateLimit(request, "siwe-link", config.siweRateLimitMax);
      const session = await authenticated(request);
      const context = await ownerFor(session);
      if (context.owner.admissionStatus !== "admitted") throw new HttpError(403, "FORBIDDEN", "Admission is required before linking a wallet");
      const opId = operationId(asRecord(request.body).operationId);
      const nonce = randomBytes(24).toString("base64url").replace(/[-_]/g, "A");
      const now = new Date();
      const expiresAt = new Date(now.getTime() + config.nonceTtlSeconds * 1000);
      const fingerprint = siweRequestFingerprint(config, request.ip, request.headers["user-agent"] ?? "");
      await db.insert(siweChallenges).values({
        nonceHash: sha256(nonce), purpose: "link", ownerId: context.owner.id,
        authSessionId: session.session.id, operationId: opId, attemptHash: fingerprint,
        createdAt: now, expiresAt, consumedAt: null
      });
      return reply.send({
        nonce, domain: new URL(config.publicOrigin).host, uri: config.publicOrigin,
        chainId: config.siweChainId, statement: "Link this wallet to Web3 Agent Bench",
        issuedAt: now.toISOString(), expiresAt, operationId: opId
      });
    } catch (error) { return responseError(reply, error); }
  });

  app.post("/api/owner/links/siwe/verify", async (request, reply) => {
    let linkOperationId: string | undefined;
    let linkOwnerId: string | undefined;
    let linkCompleted = false;
    try {
      if (config.betaManifest) throw new HttpError(403, "SIGN_IN_METHOD_DISABLED", "Wallet identity linking is disabled for the beta profile");
      await rateLimit(request, "siwe-link", config.siweRateLimitMax);
      const body = asRecord(request.body);
      const opId = operationId(body.operationId);
      linkOperationId = opId;
      const session = await authenticated(request);
      const context = await ownerFor(session);
      linkOwnerId = context.owner.id;
      if (context.owner.admissionStatus !== "admitted") throw new HttpError(403, "FORBIDDEN", "Admission is required before linking a wallet");
      if (typeof body.message !== "string" || typeof body.signature !== "string" || !/^0x(?:[\da-fA-F]{128}|[\da-fA-F]{130})$/.test(body.signature)) {
        throw new HttpError(400, "SIWE_MESSAGE_INVALID", "A signed EIP-4361 message is required");
      }
      const parsed = parseSiwe(body.message);
      const expectedDomain = new URL(config.publicOrigin).host;
      if (parsed.domain !== expectedDomain || parsed.uri !== config.publicOrigin || parsed.chainId !== config.siweChainId || parsed.statement !== "Link this wallet to Web3 Agent Bench") {
        throw new HttpError(400, "SIWE_MESSAGE_INVALID", "SIWE domain, URI, chain, or statement does not match server configuration");
      }
      const now = new Date();
      const maxMessageAge = config.nonceTtlSeconds * 1000;
      if (parsed.issuedAt.getTime() > now.getTime() + 30_000 || now.getTime() - parsed.issuedAt.getTime() > maxMessageAge ||
        (parsed.expiration && (parsed.expiration <= now || parsed.expiration.getTime() > now.getTime() + maxMessageAge + 30_000)) ||
        (parsed.notBefore && parsed.notBefore > now)) {
        throw new HttpError(400, "SIWE_MESSAGE_INVALID", "SIWE message is outside its validity window");
      }
      const address = parsed.address.toLowerCase();
      const checksumAddress = getAddress(parsed.address);
      const signature = body.signature as `0x${string}`;
      const signatureValid = await verifyMessage({ address: parsed.address as `0x${string}`, message: body.message, signature }).catch(() => false);
      if (!signatureValid) throw new HttpError(401, "SIWE_SIGNATURE_INVALID", "The wallet signature is invalid");
      const fingerprint = siweRequestFingerprint(config, request.ip, request.headers["user-agent"] ?? "");
      const challengeConsumed = await db.transaction(async (tx) => {
        const challenge = await tx.query.siweChallenges.findFirst({ where: and(
          eq(siweChallenges.nonceHash, sha256(parsed.nonce)), eq(siweChallenges.purpose, "link"),
          eq(siweChallenges.ownerId, context.owner.id), eq(siweChallenges.authSessionId, session.session.id),
          eq(siweChallenges.operationId, opId), eq(siweChallenges.attemptHash, fingerprint),
          gt(siweChallenges.expiresAt, now), isNull(siweChallenges.consumedAt)
        ) });
        if (!challenge) throw new HttpError(409, "SIWE_CHALLENGE_INVALID", "The link challenge is expired, consumed, or belongs to another session");
        const consumed = await tx.update(siweChallenges).set({ consumedAt: now }).where(and(
          eq(siweChallenges.nonceHash, challenge.nonceHash), isNull(siweChallenges.consumedAt), gt(siweChallenges.expiresAt, now)
        )).returning({ nonceHash: siweChallenges.nonceHash });
        if (consumed.length !== 1) throw new HttpError(409, "SIWE_CHALLENGE_INVALID", "The link challenge was already consumed");
        return true;
      });
      if (!challengeConsumed) throw new HttpError(409, "SIWE_CHALLENGE_INVALID", "The link challenge was already consumed");
      const result = await db.transaction(async (tx) => {
        const existingIdentity = await tx.query.identities.findFirst({
          where: and(eq(identities.provider, "wallet"), eq(identities.subject, address))
        });
        if (existingIdentity && existingIdentity.ownerId !== context.owner.id) throw identityError();
        const occupiedIdentity = await tx.query.identities.findFirst({
          where: and(eq(identities.ownerId, context.owner.id), eq(identities.provider, "wallet"))
        });
        if (occupiedIdentity && occupiedIdentity.subject !== address) throw identityError("This owner already has a different wallet linked");
        const accountId = `${checksumAddress}:${config.siweChainId}`;
        const existingAccount = await tx.query.authAccount.findFirst({
          where: and(eq(authAccount.providerId, "siwe"), eq(authAccount.accountId, accountId))
        });
        if (existingAccount && existingAccount.userId !== session.user.id) throw identityError();
        const existingWallet = await tx.query.authWalletAddress.findFirst({
          where: and(eq(authWalletAddress.address, checksumAddress), eq(authWalletAddress.chainId, config.siweChainId))
        });
        if (existingWallet && existingWallet.userId !== session.user.id) throw identityError();
        const account = await tx.insert(authAccount).values({
          id: randomUUID(), accountId, providerId: "siwe", userId: session.user.id,
          accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null,
          refreshTokenExpiresAt: null, scope: null, password: null, createdAt: now, updatedAt: now
        }).onConflictDoNothing().returning({ id: authAccount.id });
        const authAccountRow = await tx.query.authAccount.findFirst({ where: and(eq(authAccount.providerId, "siwe"), eq(authAccount.accountId, accountId)) });
        if (!authAccountRow || authAccountRow.userId !== session.user.id) throw identityError();
        const walletAddressInsert = await tx.insert(authWalletAddress).values({
          id: randomUUID(), userId: session.user.id, address: checksumAddress,
          chainId: config.siweChainId,
          isPrimary: (await tx.query.authWalletAddress.findFirst({ where: eq(authWalletAddress.userId, session.user.id) })) === undefined,
          createdAt: now
        }).onConflictDoNothing().returning({ id: authWalletAddress.id });
        const walletAddressRow = await tx.query.authWalletAddress.findFirst({ where: and(eq(authWalletAddress.address, checksumAddress), eq(authWalletAddress.chainId, config.siweChainId)) });
        if (!walletAddressRow || walletAddressRow.userId !== session.user.id) throw identityError();
        await tx.insert(identities).values({
          id: randomUUID(), ownerId: context.owner.id, authUserId: session.user.id,
          provider: "wallet", subject: address, verifiedAt: now, createdAt: now
        }).onConflictDoNothing();
        const identity = await tx.query.identities.findFirst({ where: and(eq(identities.provider, "wallet"), eq(identities.subject, address)) });
        if (!identity || identity.ownerId !== context.owner.id) throw identityError();
        const occupied = await tx.query.identities.findFirst({ where: and(eq(identities.ownerId, context.owner.id), eq(identities.provider, "wallet")) });
        if (!occupied || occupied.subject !== address) throw identityError("This owner already has a different wallet linked");
        await recordAudit(tx, "owner.identity_linked", opId, {
          actorOwnerId: context.owner.id, subjectOwnerId: context.owner.id,
          metadata: { provider: "wallet" }
        });
        await recordAudit(tx, "auth.identity_link_succeeded", opId, {
          actorOwnerId: context.owner.id, subjectOwnerId: context.owner.id,
          metadata: { provider: "wallet", purpose: "link" }
        });
        return { identity, accountAdded: account.length === 1, walletAdded: walletAddressInsert.length === 1 };
      });
      linkCompleted = true;
      return reply.send({ identity: { provider: result.identity.provider, subject: result.identity.subject, address: result.identity.subject, verifiedAt: result.identity.verifiedAt } });
    } catch (error) {
      if (linkOperationId && !linkCompleted) {
        await db.insert(auditEvents).values({
          id: randomUUID(), eventType: "auth.identity_link_failed", operationId: linkOperationId,
          actorOwnerId: linkOwnerId ?? null, subjectOwnerId: linkOwnerId ?? null,
          invitationId: null, policyRevision: null,
          metadata: { provider: "wallet", purpose: "link", reason: error instanceof HttpError ? error.code.toLowerCase() : "link_failed" },
          createdAt: new Date()
        }).catch(() => undefined);
      }
      return responseError(reply, error);
    }
  });

  const taskCoordinator = betaBefTaskCoordinator ?? localBefTaskCoordinator;
  const runMaintenanceIntervalMs = (config.localBefTaskCoordinatorEnabled || config.betaManifest)
    ? config.localBefTaskCoordinatorTickMs : 1000;
  const runMaintenanceBatchSize = 50;
  let runMaintenanceTimer: NodeJS.Timeout | undefined;
  let runMaintenanceInFlight: Promise<void> | undefined;
  let runMaintenanceStopped = false;

  async function runMaintenanceTick(): Promise<void> {
    if (runMaintenanceStopped || runMaintenanceInFlight) return;
    const work = (async () => {
      if (taskCoordinator) {
        try { await taskCoordinator.tick(); }
        catch (error) { requestSafeLog(error); }
      } else {
        try { await expireQueuedRuns(db, runMaintenanceBatchSize); }
        catch (error) { requestSafeLog(error); }
        try { await consumeRunCancellationOutbox(db, undefined, runMaintenanceBatchSize); }
        catch (error) { requestSafeLog(error); }
      }
      try { await closeExpiredTaskActions({ db }, runMaintenanceBatchSize); }
      catch (error) { requestSafeLog(error); }
      if (reportServiceDependencies) {
        try { await runReportHousekeeping(reportServiceDependencies); }
        catch (error) { requestSafeLog(error); }
      }
    })();
    runMaintenanceInFlight = work;
    try { await work; }
    finally {
      if (runMaintenanceInFlight === work) runMaintenanceInFlight = undefined;
      if (!runMaintenanceStopped) runMaintenanceTimer = setTimeout(() => {
        runMaintenanceTimer = undefined;
        void runMaintenanceTick();
      }, runMaintenanceIntervalMs);
    }
  }

  app.addHook("onClose", async () => {
    runMaintenanceStopped = true;
    if (runMaintenanceTimer) {
      clearTimeout(runMaintenanceTimer);
      runMaintenanceTimer = undefined;
    }
    await runMaintenanceInFlight;
    await taskCoordinator?.stop();
  });
  app.setErrorHandler((error, _request, reply) => responseError(reply, error));
  if (reportServiceDependencies) await runReportRetentionCleanup(reportServiceDependencies);
  await app.listen({ host: config.apiHost, port: config.apiPort });
  startupCoordinatorForCleanup = undefined;
  void runMaintenanceTick();
  app.log.info({ host: config.apiHost, port: config.apiPort, googleMode: getGoogleMode(config) }, "owner identity API listening");

  let shutdownStarted = false;
  const gracefulShutdown = async (signal: "SIGINT" | "SIGTERM") => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    try { await app.close(); }
    catch (error) { requestSafeLog(error); }
    await client.end().catch((error: unknown) => requestSafeLog(error));
    process.exitCode = signal === "SIGINT" ? 130 : 143;
  };
  process.once("SIGINT", () => { void gracefulShutdown("SIGINT"); });
  process.once("SIGTERM", () => { void gracefulShutdown("SIGTERM"); });
}

start().catch(async (error: unknown) => {
  requestSafeLog(error);
  for (const cleanupError of await cleanupFailedLocalBefTaskCoordinatorStartup(
    startupCoordinatorForCleanup, () => client.end(),
  )) requestSafeLog(cleanupError);
  startupCoordinatorForCleanup = undefined;
  process.exitCode = 1;
});
