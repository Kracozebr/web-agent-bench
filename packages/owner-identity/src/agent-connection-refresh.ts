import { createHash, randomUUID } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import type { OwnerIdentityConfig } from './config.js';
import { agentAccessGrants, agentProfiles, agentOauthAuthorizations, oauthRefreshTokens, oauthAccessTokens, owners, auditEvents } from './schema.js';
import { CONNECTION_GRANT_TTL_SECONDS, agentOAuthResource, validConnectionScopes } from './agent-connection-profile.js';
import { externalConnectionAllowed, type AgentConnectionInvalidationStore } from './agent-connection-invalidation-state.js';
import { AsyncLocalStorage } from 'node:async_hooks';

const verifiedRefreshGrant = new AsyncLocalStorage<string>();
export const currentVerifiedConnectionRefreshGrant = () => verifiedRefreshGrant.getStore();

const invalid = () => Response.json({ error: 'invalid_grant', error_description: 'Reauthorize this agent connection' },
  { status: 400, headers: { 'Cache-Control': 'no-store' } });
let activeRefreshes = 0;
const refreshWaiters: Array<() => void> = [];

/** AICODE-NOTE: The pinned provider's default token verifier is SHA-256/base64url. Its replay invalidator is client+user-wide; intercept replay before it can affect another connection. Never log request bodies. */
export async function handleConnectionTokenRequest(config: OwnerIdentityConfig, db: OwnerDatabase,
  request: Request, handler: (request: Request) => Promise<Response>, invalidationStore?: AgentConnectionInvalidationStore): Promise<Response> {
  if (config.mcpTransportProfile !== 'remote-oauth-v1') return handler(request);
  // The provider uses its own pool checkout while the fencing transaction is open. Reserve pool headroom rather than allowing every connection to wait on itself.
  if (activeRefreshes >= 4) {
    if (refreshWaiters.length >= 16) return Response.json({ error: 'temporarily_unavailable' },
      { status: 503, headers: { 'Cache-Control': 'no-store', 'Retry-After': '1' } });
    await new Promise<void>((resolve) => refreshWaiters.push(resolve));
  } else activeRefreshes += 1;
  try { return await guardedConnectionTokenRequest(config, db, request, handler, invalidationStore); }
  finally {
    const next = refreshWaiters.shift();
    if (next) next(); else activeRefreshes -= 1;
  }
}

async function guardedConnectionTokenRequest(config: OwnerIdentityConfig, db: OwnerDatabase,
  request: Request, handler: (request: Request) => Promise<Response>, invalidationStore?: AgentConnectionInvalidationStore): Promise<Response> {
  const type = request.headers.get('content-type')?.split(';')[0];
  let values: Record<string, unknown>;
  try {
    values = type === 'application/x-www-form-urlencoded'
      ? Object.fromEntries(new URLSearchParams(await request.clone().text()))
      : await request.clone().json() as Record<string, unknown>;
  } catch { return invalid(); }
  if (values.grant_type !== 'refresh_token') return handler(request);
  if (values.resource !== undefined && values.resource !== agentOAuthResource(config) ||
      values.scope !== undefined && !validConnectionScopes(config, values.scope)) return invalid();
  if (typeof values.refresh_token !== 'string' || !/^[A-Za-z]{32}$/.test(values.refresh_token) ||
      typeof values.client_id !== 'string') return invalid();
  const verifier = createHash('sha256').update(values.refresh_token).digest('base64url');
  const initial = await db.query.oauthRefreshTokens.findFirst({ where: eq(oauthRefreshTokens.token, verifier) });
  if (!initial?.referenceId || initial.clientId !== values.client_id) return invalid();
  const initialGrant = await db.query.agentAccessGrants.findFirst({ where: eq(agentAccessGrants.id, initial.referenceId) });
  if (!initialGrant) return invalid();
  // Restored APIs can be read-only. Reject known fenced credentials with reads before any FOR UPDATE; a legitimate rotated-token retry still reaches the full locked validation below.
  if (initialGrant.revokedAt || initial.expiresAt <= new Date() ||
      !(await externalConnectionAllowed(invalidationStore,
        { ownerId: initialGrant.ownerId, agentId: initialGrant.agentId, grantId: initialGrant.id, accessGeneration: initialGrant.accessGeneration }, db))) return invalid();
  return db.transaction(async (tx) => {
    // Matches AAP revoke/BRL admission lock order. Across workers, simultaneous refresh retries wait for the persisted encrypted replay result.
    await tx.execute(sql`SELECT id FROM oid_agent WHERE id=${initialGrant.agentId} FOR UPDATE`);
    const token = await tx.query.oauthRefreshTokens.findFirst({ where: eq(oauthRefreshTokens.token, verifier) });
    const grant = await tx.query.agentAccessGrants.findFirst({ where: eq(agentAccessGrants.id, initialGrant.id) });
    const profile = await tx.query.agentProfiles.findFirst({ where: eq(agentProfiles.id, initialGrant.agentId) });
    const owner = await tx.query.owners.findFirst({ where: eq(owners.id, initialGrant.ownerId) });
    const authorization = await tx.query.agentOauthAuthorizations.findFirst({ where: eq(agentOauthAuthorizations.grantId, initialGrant.id) });
    const now = new Date();
    if (!token || !grant || !profile || !owner || !authorization || authorization.status !== 'approved' ||
        !authorization.authorizationCodeHash || authorization.ownerId !== grant.ownerId || authorization.agentId !== grant.agentId ||
        authorization.authUserId !== owner.authUserId || authorization.clientId !== grant.oauthClientId ||
        authorization.resource !== grant.resource || authorization.accessGeneration !== grant.accessGeneration ||
        grant.source !== 'oauth' || grant.revokedAt ||
        token.expiresAt <= now || profile.accessRevokedAt ||
        owner.admissionStatus !== 'admitted' || owner.authUserId !== token.userId ||
        grant.oauthClientId !== token.clientId || grant.accessGeneration !== profile.accessGeneration ||
        grant.resource !== agentOAuthResource(config)) return invalid();
    if (!(await externalConnectionAllowed(invalidationStore,
      { ownerId: grant.ownerId, agentId: grant.agentId, grantId: grant.id, accessGeneration: grant.accessGeneration }, db))) return invalid();
    if (token.revoked && (!token.rotatedAt || !token.rotationReplayExpiresAt || token.rotationReplayExpiresAt < now)) {
      await invalidationStore?.appendIntent({ kind: 'connection_revoke', operationId: `refresh-replay:${token.id}`,
        ownerId: grant.ownerId, agentId: grant.agentId, connectionId: grant.id });
      await tx.update(agentAccessGrants).set({ revokedAt: now, revocationReason: 'refresh_replay' }).where(eq(agentAccessGrants.id, grant.id));
      await tx.update(oauthRefreshTokens).set({ revoked: now, rotationReplayResponse: null, rotationReplayExpiresAt: null })
        .where(eq(oauthRefreshTokens.referenceId, grant.id));
      await tx.update(oauthAccessTokens).set({ revoked: now }).where(eq(oauthAccessTokens.referenceId, grant.id));
      await tx.insert(auditEvents).values({ id: randomUUID(), eventType: 'agent.connection.refresh_replay_denied',
        operationId: `refresh-replay:${randomUUID()}`, actorOwnerId: owner.id, subjectOwnerId: owner.id,
        metadata: { agentId: profile.id, connectionId: grant.id, scope: 'connection' }, createdAt: now });
      return invalid();
    }
    if (!token.revoked) await invalidationStore?.appendIntent({ kind: 'refresh_consume', operationId: `refresh-consume:${token.id}`,
      ownerId: grant.ownerId, agentId: grant.agentId, connectionId: grant.id, consumedRefreshHash: verifier });
    const response = await verifiedRefreshGrant.run(grant.id, () => handler(request));
    if (response.ok) {
      // Sliding inactivity bound, same stable connection/generation and current owner policy. Active refresh does not require scheduled re-consent.
      await tx.update(agentAccessGrants).set({ expiresAt: new Date(now.getTime() + CONNECTION_GRANT_TTL_SECONDS * 1000) })
        .where(and(eq(agentAccessGrants.id, grant.id), sql`${agentAccessGrants.revokedAt} IS NULL`));
    }
    return response;
  });
}
