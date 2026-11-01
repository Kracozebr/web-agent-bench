import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from './config.js';
import { agentOAuthResource, connectionHealth, remoteConnectionSetup } from './agent-connection-profile.js';
import { selectAgentMcpTransport } from './agent-mcp-profile.js';
const config = loadConfig({ OID_DATABASE_URL: 'postgres://test.invalid/local', OID_AUTH_SECRET: 'fixture-only-value-with-at-least-thirty-two-characters',
  OID_MCP_TRANSPORT_PROFILE: 'remote-oauth-v1', NODE_ENV: 'test' });
const headers = { accept: 'application/json, text/event-stream' };

test('remote OAuth preserves exact native fixed and server-specific callbacks while rejecting substitution and traversal', () => {
  const env = { OID_DATABASE_URL: 'postgres://test.invalid/local',
    OID_AUTH_SECRET: 'fixture-only-value-with-at-least-thirty-two-characters',
    OID_MCP_TRANSPORT_PROFILE: 'remote-oauth-v1', NODE_ENV: 'test' };
  for (const pathname of ['/callback', '/callback/serverID']) {
    const callback = `http://127.0.0.1:38765${pathname}`;
    const loaded = loadConfig({ ...env, OID_MCP_CLIENT_REDIRECT_URI: callback });
    assert.equal(loaded.mcpClientRedirectUri, callback);
    assert.deepEqual(loaded.mcpClientRegistry?.[0]?.redirectUris, [callback],
      'the configured callback must be registered verbatim, without prefix matching or callback rewriting');
  }
  for (const callback of [
    'http://foreign.invalid:38765/callback', 'http://localhost:38765/callback',
    'http://127.0.0.1:38765/callback?next=foreign', 'http://127.0.0.1:38765/callback#fragment',
    'http://user:password@127.0.0.1:38765/callback', 'https://127.0.0.1:38765/callback',
    'http://127.0.0.1/callback', 'http://127.0.0.1:38765/callback/../serverID',
    'http://127.0.0.1:38765/callback/%2e%2e/serverID', 'http://127.0.0.1:38765/callback/%252e%252e/serverID',
    'http://127.0.0.1:38765/callback//serverID',
  ]) assert.throws(() => loadConfig({ ...env, OID_MCP_CLIENT_REDIRECT_URI: callback }), /OID_MCP_CLIENT_REDIRECT_URI/, callback);
});

test('legacy strict callback policy remains exact and does not inherit native remote callback paths', () => {
  const env = { OID_DATABASE_URL: 'postgres://test.invalid/local',
    OID_AUTH_SECRET: 'fixture-only-value-with-at-least-thirty-two-characters', NODE_ENV: 'test' };
  const legacy = 'http://127.0.0.1:38765/oauth/callback';
  assert.equal(loadConfig({ ...env, OID_MCP_CLIENT_REDIRECT_URI: legacy }).mcpClientRedirectUri, legacy);
  for (const pathname of ['/callback', '/callback/serverID', '/oauth/callback-extra']) {
    assert.throws(() => loadConfig({ ...env, OID_MCP_CLIENT_REDIRECT_URI: `http://127.0.0.1:38765${pathname}` }), /OID_MCP_CLIENT_REDIRECT_URI/);
  }
});

test('remote endpoint rejects substituted origin and discloses honest qualification and URL fallback', () => {
  const setup = remoteConnectionSetup(config);
  assert.equal(setup.serverUrl, 'http://127.0.0.1:3000/api/agent/mcp');
  assert.equal(setup.resource, setup.serverUrl);
  assert.equal(setup.environment, 'loopback-development');
  assert.equal(setup.setup.nativeAddUrl, null);
  assert.ok(setup.clients.every((client) => client.qualification === 'unverified' && client.nativeAddUrl === null));
  for (const publicOrigin of ['http://example.invalid', 'https://example.invalid/path', 'https://user:pass@example.invalid']) {
    assert.throws(() => remoteConnectionSetup({ ...config, publicOrigin }));
  }
  assert.throws(() => remoteConnectionSetup({ ...config, nodeEnv: 'production' }));
});

test('only remote OAuth binds the exact MCP endpoint; legacy resource identities remain unchanged', () => {
  assert.equal(agentOAuthResource(config), `${config.publicOrigin}/api/agent/mcp`);
  for (const mcpTransportProfile of ['strict-2026-07-28', 'codex-local-manual-2025-06-18', 'beta-remote-v1'] as const) {
    assert.equal(agentOAuthResource({ ...config, mcpTransportProfile }), `${config.publicOrigin}/api/agent`);
  }
});

test('remote transport negotiates actual protocol without client version allowlist or metadata authority', () => {
  for (const name of ['codex-mcp-client', 'unknown-client']) for (const version of ['0.165.0', '99.0.0']) {
    const request = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', clientInfo: { name, version }, capabilities: {} } };
    assert.equal(selectAgentMcpTransport(config, false, request, headers, 'registered-client'), 'remote-oauth');
    assert.throws(() => selectAgentMcpTransport(config, false, { ...request, params: { ...request.params, protocolVersion: '2099-01-01' } }, headers));
  }
  const modern = { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'identity.preflight', arguments: {} } };
  assert.throws(() => selectAgentMcpTransport(config, false, modern, { ...headers, 'mcp-protocol-version': '2026-07-28' }));
  assert.equal(selectAgentMcpTransport(config, false, modern, { ...headers, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'identity.preflight' }), 'remote-oauth');
});

test('connection health separates authorization, actual preflight timestamp, offline, expiry, and revoke', () => {
  const now = new Date('2026-10-31T12:00:00Z');
  const grant = { revokedAt: null, expiresAt: new Date(now.getTime() + 60_000) };
  assert.equal(connectionHealth(grant, null, now), 'authorized');
  assert.equal(connectionHealth(grant, now, now), 'preflight-verified');
  assert.equal(connectionHealth(grant, new Date(now.getTime() - 300_001), now), 'offline');
  assert.equal(connectionHealth({ ...grant, expiresAt: now }, now, now), 'expired');
  assert.equal(connectionHealth({ ...grant, revokedAt: now }, now, now), 'revoked');
});
