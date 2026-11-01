import assert from 'node:assert/strict';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as identitySchema from './schema.js';
import type { OwnerDatabase } from './db.js';
import { createDatabase } from './db.js';
import { createAuth } from './auth.js';
import { loadConfig } from './config.js';
import { handleConnectionTokenRequest } from './agent-connection-refresh.js';
import { agentOAuthResource } from './agent-connection-profile.js';
import { issueBonusGrant } from './ledger.js';
import { createLaunchIntent, acceptLaunchIntent, type RunServiceDependencies } from './run-service.js';
import type { RunAdmissionRelease } from './task-release.js';
import Fastify, { type FastifyInstance } from 'fastify';
import { registerAgentRoutes } from './agents.js';
import { HttpError } from './http-error.js';
import type { AgentMcpAcceptanceEvent } from './agent-mcp-acceptance-observer.js';
import { createAgentConnectionInvalidationStore, initializeAgentConnectionInvalidationState, externalConnectionAllowed, reconcileAgentConnectionInvalidation } from './agent-connection-invalidation-state.js';

const enabled = process.env.OID_ACI_CONNECTION_PG_TEST === '1';
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const refreshSecret = () => randomBytes(32).toString('hex').slice(0, 32).replace(/[0-9]/g, 'Q');
function mcpPayload(body: string) {
  const data = body.split(/\r?\n/).find((line) => line.startsWith('data: '));
  return JSON.parse(data ? data.slice(6) : body);
}

test('remote refresh keeps one connection, survives response loss, slides inactivity bound, and fences only replayed connection',
  { skip: !enabled, timeout: 120_000 }, async () => {
  const source = new URL(process.env.OID_DATABASE_URL ?? `postgres://oid_owner:${(await readFile('/run/secrets/owner_password', 'utf8')).trim()}@postgres/owner_identity`);
  assert.equal(source.hostname, 'postgres'); assert.equal(source.username, 'oid_owner'); assert.equal(source.pathname, '/owner_identity');
  const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
  const target = new URL(source); target.pathname = `/${databaseName}`;
  const admin = postgres(source.href, { max: 1 });
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', OID_DATABASE_URL: target.href,
    OID_AUTH_SECRET: 'disposable-fixture-auth-secret-at-least-thirty-two-characters', OID_MCP_TRANSPORT_PROFILE: 'remote-oauth-v1',
    OID_MCP_CLIENT_ID: 'oid-fixture-remote-mcp-client',
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'false', OID_PUBLIC_ORIGIN: 'http://127.0.0.1:3000' });
  const { client, db } = createDatabase(config);
  let app: FastifyInstance | undefined;
  let invalidationRoot: string | undefined;
  try {
    await admin.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
    const runMigration = (profile: string) => spawnSync(process.execPath, ['--import', './packages/owner-identity/node_modules/tsx/dist/loader.mjs', 'packages/owner-identity/src/migrate.ts'],
      { cwd: '/workspace', env: { ...process.env, NODE_ENV: 'test', OID_DATABASE_URL: target.href, OID_AUTH_SECRET: config.authSecret,
        OID_MCP_TRANSPORT_PROFILE: profile, OID_MCP_CLIENT_ID: profile === 'remote-oauth-v1' ? config.mcpClientId : 'oid-local-mcp-client',
        OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'false', OID_PUBLIC_ORIGIN: config.publicOrigin }, encoding: 'utf8', timeout: 60_000 });
    const legacyMigration = runMigration('strict-2026-07-28');
    assert.equal(legacyMigration.status, 0, 'Initial legacy fixture migration must succeed');
    const migration = runMigration('remote-oauth-v1');
    assert.equal(migration.status, 0, `Disposable fixture migration failed: ${migration.stderr}`);
    const userId = randomUUID(), ownerId = randomUUID(), agentId = randomUUID(), sessionId = randomUUID();
    await client`INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES(${userId},'ACI fixture',${`${userId}@example.invalid`},true)`;
    await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${ownerId},${userId},'admitted')`;
    await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agentId},${ownerId},'ACI fixture')`;
    await client`INSERT INTO oid_agent_policy(agent_id) VALUES(${agentId})`;
    await client`INSERT INTO oid_auth_session(id,user_id,token,expires_at) VALUES(${sessionId},${userId},${randomUUID()},now()+interval '40 days')`;
    const resource = agentOAuthResource(config);
    const resources = await client`SELECT identifier FROM oid_oauth_resource ORDER BY identifier`;
    assert.deepEqual(resources.map((row) => row.identifier), [`${config.publicOrigin}/api/agent`, resource]);
    const seedConnection = async () => {
      const grantId = randomUUID(), secret = refreshSecret();
      await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,oauth_client_id,resource,role,access_generation,created_at,expires_at)
        VALUES(${grantId},${ownerId},${agentId},${randomUUID()},'oauth',${config.mcpClientId},${resource},'agent',1,now()-interval '29 days',now()+interval '1 day')`;
      await client`INSERT INTO oid_agent_oauth_authorization(id,operation_id,query_hash,owner_id,auth_user_id,auth_session_id,agent_id,grant_id,client_id,resource,redirect_uri,scopes,authorization_code_hash,access_generation,policy_revision,status,created_at,expires_at)
        VALUES(${randomUUID()},${randomUUID()},${randomUUID()},${ownerId},${userId},${sessionId},${agentId},${grantId},${config.mcpClientId},${resource},${config.mcpClientRedirectUri},ARRAY['agent:operate'],${randomUUID()},1,1,'approved',now(),now()+interval '10 minutes')`;
      await client`INSERT INTO oid_oauth_refresh_token(id,token,client_id,session_id,user_id,reference_id,resources,expires_at,created_at,scopes)
        VALUES(${randomUUID()},${digest(secret)},${config.mcpClientId},${sessionId},${userId},${grantId},ARRAY[${resource}],now()+interval '1 day',now()-interval '29 days',ARRAY['agent:operate','offline_access'])`;
      return { grantId, secret };
    };
    const a = await seedConnection(), b = await seedConnection();
    const auth = createAuth(config, db);
    const call = async (secret: string) => handleConnectionTokenRequest(config, db, new Request(`${config.publicOrigin}/api/auth/oauth2/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: secret, client_id: config.mcpClientId, resource }),
    }), (request) => auth.handler(request));
    // A crash after provider rotation can leave an old grant-expiry projection. A still-valid refresh credential is authoritative for renewal; it never revives revoked access.
    await client`UPDATE oid_agent_access_grant SET expires_at=now()-interval '1 second' WHERE id=${a.grantId}`;
    const fresh = await call(a.secret);
    assert.equal(fresh.status, 200, `Refresh failed with status ${fresh.status}`);
    const tokens = await fresh.json() as { access_token: string; refresh_token: string };
    assert.ok(tokens.access_token); assert.ok(tokens.refresh_token); assert.notEqual(tokens.refresh_token, a.secret);
    const claims = await auth.api.verifyJWT({ body: { token: tokens.access_token, issuer: `${config.publicOrigin}/api/auth` } });
    assert.equal(claims.payload?.aud, resource, 'The actual provider issues only the exact endpoint audience');
    const wrongResourceRequest = new Request(`${config.publicOrigin}/api/auth/oauth2/token`, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
        client_id: config.mcpClientId, resource: `${config.publicOrigin}/api/agent` }) });
    assert.equal((await handleConnectionTokenRequest(config, db, wrongResourceRequest, (request) => auth.handler(request))).status, 400,
      'A legacy resource alias cannot renew this remote grant');
    app = Fastify({ logger: false });
    app.setErrorHandler((error, _request, reply) => reply.code(error instanceof HttpError ? error.status : 500).send({ error: error instanceof HttpError ? error.code : 'INTERNAL_ERROR' }));
    const observedMcp: AgentMcpAcceptanceEvent[] = [];
    registerAgentRoutes(app, { db, auth, config,
      observeAgentMcp(event) { observedMcp.push(event); if (event.phase === 'response') throw new Error('fixture observer failure must preserve HTTP'); },
      async resolveOwner() { return { owner: { id: ownerId, authUserId: userId, admissionStatus: 'admitted' } }; },
      async requireOrigin(request) { if (request.headers.origin !== config.publicOrigin) throw new HttpError(403, 'ORIGIN_NOT_ALLOWED', 'Origin required'); },
      async rateLimit() {}, rateLimitMax: 30, credentialRateLimitMax: 30, preflightRateLimitMax: 60,
      manualCredentialTtlSeconds: 3600, agentResource: resource, agentPreflightUrl: `${resource}/preflight` });
    const wireHeaders = { host: '127.0.0.1:3000', authorization: `Bearer ${tokens.access_token}`,
      'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' };
    const initialized = await app.inject({ method: 'POST', url: '/api/agent/mcp', headers: wireHeaders,
      payload: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'unlisted-fixture-client', version: 'future-version' } } } });
    assert.equal(initialized.statusCode, 200);
    assert.equal(mcpPayload(initialized.body).result.protocolVersion, '2025-06-18');
    assert.equal(observedMcp.length, 2);
    assert.equal(observedMcp[0]!.requestId, observedMcp[1]!.requestId);
    assert.deepEqual(observedMcp[0]!.principal, { ownerId, agentId, grantId: a.grantId });
    assert.deepEqual(observedMcp[1]!.body, mcpPayload(initialized.body));
    const checked = await app.inject({ method: 'POST', url: '/api/agent/mcp', headers: wireHeaders,
      payload: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'identity.preflight', arguments: { operationId: `check_${randomUUID().replaceAll('-', '')}` } } } });
    assert.equal(checked.statusCode, 200);
    assert.equal(mcpPayload(checked.body).result.structuredContent.status, 'allowed');
    assert.ok(Date.parse(mcpPayload(checked.body).result.structuredContent.checkedAt));
    assert.deepEqual(mcpPayload(checked.body).result.structuredContent.identity, { agentId, connectionId: a.grantId });
    assert.equal(mcpPayload(checked.body).result.structuredContent.permissions.training, false);
    assert.equal(mcpPayload(checked.body).result.structuredContent.protocolVersion, '2025-06-18');
    const status = await app.inject({ method: 'GET', url: `/api/owner/agents/${agentId}/connections` });
    assert.equal(status.statusCode, 200);
    const observed = status.json().connections.find((connection: {id: string}) => connection.id === a.grantId);
    assert.equal(observed.status, 'preflight-verified');
    assert.equal(observed.protocolVersion, '2025-06-18');
    assert.ok(observed.lastPreflightAt);
    const retry = await call(a.secret); assert.equal(retry.status, 200);
    const recovered = await retry.json() as typeof tokens;
    assert.equal(recovered.access_token, tokens.access_token); assert.equal(recovered.refresh_token, tokens.refresh_token);
    const [renewed] = await client`SELECT expires_at,access_generation FROM oid_agent_access_grant WHERE id=${a.grantId}`;
    assert.ok(new Date(renewed!.expires_at).getTime() > Date.now() + 29 * 86400_000);
    assert.equal(renewed!.access_generation, 1);
    const freshRows = await client`SELECT reference_id FROM oid_oauth_refresh_token WHERE token=${digest(tokens.refresh_token)}`;
    assert.equal(freshRows[0]!.reference_id, a.grantId);
    await client`UPDATE oid_oauth_refresh_token SET rotation_replay_expires_at=now()-interval '1 second' WHERE token=${digest(a.secret)}`;
    assert.equal((await call(a.secret)).status, 400);
    assert.equal((await call(tokens.refresh_token)).status, 400);
    assert.equal((await call(b.secret)).status, 200, 'Replay must preserve another connection for this same owner, agent and OAuth client');
    const c = await seedConnection();
    const concurrent = await Promise.all([call(c.secret), call(c.secret)]);
    assert.ok(concurrent.every((response) => response.status === 200));
    const concurrentTokens = await Promise.all(concurrent.map((response) => response.json())) as Array<typeof tokens>;
    assert.equal(concurrentTokens[0]!.refresh_token, concurrentTokens[1]!.refresh_token);
    assert.equal(concurrentTokens[0]!.access_token, concurrentTokens[1]!.access_token);
    const wrongClient = new Request(`${config.publicOrigin}/api/auth/oauth2/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: c.secret, client_id: 'foreign-client', resource }),
    });
    assert.equal((await handleConnectionTokenRequest(config, db, wrongClient, (request) => auth.handler(request))).status, 400);
    await client`UPDATE oid_agent_access_grant SET revoked_at=now(),revocation_reason='owner_connection_revoke' WHERE id=${c.grantId}`;
    assert.equal((await call(c.secret)).status, 400, 'Revocation must deny even a cached lost-response retry');
    assert.equal((await call(concurrentTokens[0]!.refresh_token)).status, 400);
    const revoked = await client`SELECT id FROM oid_agent_access_grant WHERE id=${a.grantId} AND revoked_at IS NOT NULL AND revocation_reason='refresh_replay'`;
    assert.equal(revoked.length, 1);
    const policy = await client`SELECT training,ranked,forum_messages,custom_topics,revision FROM oid_agent_policy WHERE agent_id=${agentId}`;
    assert.deepEqual(policy[0], { training: false, ranked: false, forum_messages: false, custom_topics: false, revision: 1 });
    for (const table of ['oid_benchmark_run', 'oid_run_launch_intent', 'oid_run_reservation', 'oid_ledger_entry']) {
      assert.equal((await client.unsafe(`SELECT count(*)::int AS count FROM ${table}`))[0]!.count, 0);
    }
    // A separate business fixture begins here: the preceding free refresh/preflight boundary has zero financial effects.
    await client`UPDATE oid_agent_policy SET training=true WHERE agent_id=${agentId}`;
    await client`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,operation_limit_units,utc_day_limit_units,category_limits,revision)
      VALUES(${ownerId},${agentId},false,NULL,NULL,'{"benchmark":null,"forum":null}'::jsonb,1)`;
    await issueBonusGrant(db, { actorOwnerId: ownerId, ownerId, operationId: `bonus_${randomUUID().replaceAll('-', '')}`,
      amount: '1.000000', reason: 'Disposable ACI selected connection fixture' });
    const release: RunAdmissionRelease = { releaseIdentity: 'aci-pg/v1', benchmarkVersion: 'aci-pg/v1',
      manifestHash: 'a'.repeat(64), benchmarkHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), mode: 'training',
      taskIds: ['S1', 'M1', 'H1'], weights: [1, 2, 3], priceUnits: '600000', precision: 6 };
    const deps: RunServiceDependencies = { db, bonusOnly: true,
      admissionReleaseProvider: { async getActiveAdmissionRelease() { return release; }, async getValidatedRelease() { return null; }, getPublicCatalog() { return []; } },
      intentTtlSeconds: 900, maxIntentTtlSeconds: 3600, queueWaitSeconds: 3600, maxQueueWaitSeconds: 86400,
      executionCapacity: 1, maxPendingIntentsPerOwner: 8, maxPendingIntentsGlobal: 20,
      maxAcceptedRunsPerOwner: 4, maxAcceptedRunsGlobal: 20 };
    const op = () => `aci_${randomUUID().replaceAll('-', '')}`;
    const launch = { ownerId, agentId, selectedConnectionId: b.grantId, mode: 'training' as const, taskIds: ['S1'], cashCeiling: '0',
      expectedReleaseIdentity: release.releaseIdentity, expectedManifestHash: release.manifestHash, expectedQuotePrice: '0.100000', operationId: op() };
    const intent = await createLaunchIntent(deps, launch);
    assert.equal((await createLaunchIntent(deps, launch)).intent.id, intent.intent.id);
    const d = await seedConnection();
    const accept = { intentId: intent.intent.id, ownerId, agentId, accessGeneration: 1, operationId: op(),
      verifiedGrant: { id: b.grantId, resource } };
    const code = (expected: string) => (error: unknown) => { assert.equal((error as {code?: string}).code, expected); return true; };
    await assert.rejects(createLaunchIntent(deps, { ...launch, selectedConnectionId: d.grantId }), code('IDEMPOTENCY_CONFLICT'));
    await assert.rejects(createLaunchIntent(deps, { ...launch, operationId: op(), selectedConnectionId: randomUUID() }), code('CONNECTION_UNAVAILABLE'));
    await assert.rejects(acceptLaunchIntent(deps, { ...accept, verifiedGrant: { id: d.grantId, resource } }), code('CONNECTION_INTENT_MISMATCH'));
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_benchmark_run`)[0]!.count, 0);
    const bTokens = await (await call(b.secret)).json() as typeof tokens;
    assert.equal((await call(bTokens.refresh_token)).status, 200, 'Access rotation between browser intent and acceptance preserves the stable connection');
    const run = await acceptLaunchIntent(deps, accept);
    assert.equal((await acceptLaunchIntent(deps, { ...accept, operationId: op() })).run.id, run.run.id);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_benchmark_run`)[0]!.count, 1);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_run_reservation`)[0]!.count, 1);
    await client`UPDATE oid_agent_access_grant SET revoked_at=now(),revocation_reason='owner_connection_revoke' WHERE id=${b.grantId}`;
    await assert.rejects(acceptLaunchIntent(deps, accept), code('AGENT_ACCESS_REVOKED'), 'Revocation denies before a cached successful admission replay');
    const activeOther = await client`SELECT id FROM oid_agent_access_grant WHERE id=${d.grantId} AND revoked_at IS NULL`;
    assert.equal(activeOther.length, 1);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_benchmark_run`)[0]!.count, 1);
    const revokeOperation = op();
    const revokeRequest = { method: 'POST' as const, url: `/api/owner/agents/${agentId}/connections/${d.grantId}/revoke`,
      headers: { origin: config.publicOrigin }, payload: { operationId: revokeOperation } };
    const revokedHttp = await app.inject(revokeRequest);
    assert.equal(revokedHttp.statusCode, 200);
    assert.equal(revokedHttp.json().connectionId, d.grantId);
    assert.deepEqual((await app.inject(revokeRequest)).json(), revokedHttp.json());
    const forbiddenRevoke = await app.inject({ ...revokeRequest, headers: { origin: 'https://foreign.invalid' } });
    assert.equal(forbiddenRevoke.statusCode, 403);
    const deniedMcp = await app.inject({ method: 'POST', url: '/api/agent/mcp', headers: wireHeaders,
      payload: { jsonrpc: '2.0', id: 3, method: 'tools/list' } });
    assert.equal(deniedMcp.statusCode, 401);
    assert.match(String(deniedMcp.headers['www-authenticate']), /resource_metadata=/);
    // Component rollback fixture, not a physical cold-restore acceptance claim.
    invalidationRoot = await mkdtemp(join(tmpdir(), 'aci-invalidation-pg-'));
    const journalPath = join(invalidationRoot, 'journal.json'), floorPath = join(invalidationRoot, 'floor.json'), journalId = randomUUID();
    await initializeAgentConnectionInvalidationState({ journalPath, floorPath, journalId });
    const store = createAgentConnectionInvalidationStore({ journalPath, floorPath, expectedJournalId: journalId });
    const e = await seedConnection(), f = await seedConnection(), g = await seedConnection();
    const storedCall = async (secret: string) => handleConnectionTokenRequest(config, db,
      new Request(`${config.publicOrigin}/api/auth/oauth2/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: secret, client_id: config.mcpClientId, resource }) }), (request) => auth.handler(request), store);
    const rotation = await storedCall(e.secret); assert.equal(rotation.status, 200);
    const rotationTokens = await rotation.json() as typeof tokens;
    const rotationRetry = await storedCall(e.secret); assert.equal(rotationRetry.status, 200, 'external consumption preserves legitimate encrypted retry');
    assert.equal((await rotationRetry.json() as typeof tokens).refresh_token, rotationTokens.refresh_token);
    const principal = (grantId: string) => ({ ownerId, agentId, grantId, accessGeneration: 1 });
    assert.equal(await externalConnectionAllowed(store, principal(e.grantId), db), true);
    await client`UPDATE oid_oauth_refresh_token SET revoked=NULL,rotated_at=NULL,rotation_replay_response=NULL,rotation_replay_expires_at=NULL WHERE token=${digest(e.secret)}`;
    assert.equal(await externalConnectionAllowed(store, principal(e.grantId), db), false, 'stale active consumption rejects access before writes are enabled');
    assert.equal((await storedCall(rotationTokens.refresh_token)).status, 400);
    const gTokens = await (await call(g.secret)).json() as typeof tokens;
    const fTokens = await (await call(f.secret)).json() as typeof tokens;
    await store.appendIntent({ kind: 'connection_revoke', operationId: `revoke_${randomUUID()}`, ownerId, agentId, connectionId: g.grantId });
    assert.equal(await externalConnectionAllowed(store, principal(g.grantId), db), false, 'journal intent fences even before SQL acknowledgement');
    const gate = Fastify({ logger: false });
    registerAgentRoutes(gate, { db, auth, config, invalidationStore: store,
      async resolveOwner() { return { owner: { id: ownerId, authUserId: userId, admissionStatus: 'admitted' } }; },
      async requireOrigin() {}, async rateLimit() {}, rateLimitMax: 30, credentialRateLimitMax: 30, preflightRateLimitMax: 60,
      manualCredentialTtlSeconds: 3600, agentResource: resource, agentPreflightUrl: `${config.publicOrigin}/api/agent/preflight` });
    try {
      for (const token of [gTokens.access_token, rotationTokens.access_token]) {
        const denied = await gate.inject({ method: 'POST', url: '/api/agent/mcp', headers: { ...wireHeaders, authorization: `Bearer ${token}` },
          payload: { jsonrpc: '2.0', id: 11, method: 'tools/list' } });
        assert.equal(denied.statusCode, 401, 'stale revoked/uncertain rotation JWT denied by actual MCP ingress before write-enable');
        assert.match(String(denied.headers['www-authenticate']), /resource_metadata=/);
      }
      const other = await gate.inject({ method: 'POST', url: '/api/agent/mcp', headers: { ...wireHeaders, authorization: `Bearer ${fTokens.access_token}` },
        payload: { jsonrpc: '2.0', id: 12, method: 'tools/list' } });
      assert.equal(other.statusCode, 200, 'unaffected connection remains authorized at real MCP ingress');
    } finally { await gate.close(); }
    const businessFingerprint = async () => (await client`SELECT
      (SELECT md5(COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id)::text,'[]')) FROM oid_benchmark_run r) AS runs,
      (SELECT md5(COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id)::text,'[]')) FROM oid_ledger_entry r) AS ledger,
      (SELECT md5(COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id)::text,'[]')) FROM oid_run_reservation r) AS reservations`)[0];
    const businessBefore = await businessFingerprint();
    const reconciled = await reconcileAgentConnectionInvalidation(db, store);
    assert.equal(reconciled.fencedConnections, 2);
    assert.equal((await client`SELECT id FROM oid_agent_access_grant WHERE id IN (${e.grantId},${g.grantId}) AND revoked_at IS NOT NULL`).length, 2);
    assert.equal((await client`SELECT id FROM oid_agent_access_grant WHERE id=${f.grantId} AND revoked_at IS NULL`).length, 1);
    const readOnlyClient = postgres(target.href, { max: 1, connection: { default_transaction_read_only: true } });
    const readOnlyDb = drizzle(readOnlyClient, { schema: identitySchema }) as unknown as OwnerDatabase;
    try {
      assert.equal((await readOnlyClient`SELECT current_setting('default_transaction_read_only') AS mode`)[0]!.mode, 'on');
      for (const secret of [e.secret, rotationTokens.refresh_token, gTokens.refresh_token]) {
        const request = new Request(`${config.publicOrigin}/api/auth/oauth2/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: secret, client_id: config.mcpClientId, resource }) });
        const denied = await handleConnectionTokenRequest(config, readOnlyDb, request,
          async () => { throw new Error('Revoked refresh must not reach provider or acquire a write lock'); }, store);
        assert.equal(denied.status, 400, 'readonly restored token endpoint returns invalid_grant rather than FOR UPDATE error');
        assert.equal((await denied.json() as {error: string}).error, 'invalid_grant');
      }
    } finally { await readOnlyClient.end(); }
    assert.deepEqual(await businessFingerprint(), businessBefore);
    const otherAgent = randomUUID();
    await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${otherAgent},${ownerId},'Unaffected fixture agent')`;
    await client`INSERT INTO oid_agent_policy(agent_id) VALUES(${otherAgent})`;
    await store.appendIntent({ kind: 'agent_revoke', operationId: `global_${randomUUID()}`, ownerId, agentId, generationFloor: 2 });
    await reconcileAgentConnectionInvalidation(db, store);
    await reconcileAgentConnectionInvalidation(db, store);
    assert.equal((await client`SELECT access_generation FROM oid_agent WHERE id=${agentId}`)[0]!.access_generation, 2);
    assert.equal((await client`SELECT access_generation FROM oid_agent WHERE id=${otherAgent}`)[0]!.access_generation, 1);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_agent_cancellation_outbox WHERE agent_id=${agentId} AND access_generation=2`)[0]!.count, 1);
    assert.deepEqual(await businessFingerprint(), businessBefore, 'startup materializes AAP fences/outbox without cancelling or charging work itself');
  } finally {
    await app?.close();
    await client.end();
    await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
    await admin.end();
    if (invalidationRoot) await rm(invalidationRoot, { recursive: true, force: true });
  }
});
