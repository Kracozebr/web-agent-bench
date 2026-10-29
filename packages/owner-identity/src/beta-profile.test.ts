import assert from 'node:assert/strict';
import test from 'node:test';
import { BetaDeploymentManifestSchema, isAddressInCidrs, isQualificationReadPeerAllowed } from './beta-profile.js';
import { loadConfig } from './config.js';
import { selectAgentMcpTransport } from './agent-mcp-profile.js';

const hash = 'a'.repeat(64);
function qualificationManifest(readCidrs = ['203.0.113.0/24']) {
  const disabled = (family: string) => ({ family, enabled: false, verificationStatus: 'unverified', edition: null,
    version: null, platform: null, mcpClientName: null, mcpClientVersion: null, protocolVersions: [], authMethods: [],
    oauthClientId: null, redirectUris: [], verificationEvidenceSha256: [] });
  return {
    schemaVersion: 'beta-deployment-manifest/v1', state: 'qualification', executionProfileId: 'beta-bef-v1',
    transportProfileId: 'beta-remote-v1',
    source: { commit: 'b'.repeat(40), applicationBuildSha256: hash, evaluatorSourceSha256: hash },
    publicOrigin: 'https://bench.example', apiBindHost: '127.0.0.1', apiPort: 8784,
    trustedProxyCidrs: ['192.0.2.10/32'], qualificationReadCidrs: readCidrs,
    google: { issuer: 'https://accounts.google.com', clientId: 'fixture-client-id',
      callbackUri: 'https://bench.example/api/auth/callback/google', adminSubject: 'fixture-admin-subject' },
    release: { releaseIdentity: 'fixture-release', manifestHash: hash, benchmarkHash: hash, policyHash: hash,
      benchmarkVersion: 'fixture-v1', executionIdentityHash: hash, environmentManifestSha256: hash,
      applicationSourceSha256: hash, sourceBlockHash: hash },
    queue: { executionCapacity: 1, maxAcceptedPerOwner: 2, maxAcceptedGlobal: 8, maxPendingPerOwner: 2,
      maxPendingGlobal: 30, queueWaitSeconds: 86400, successorPreparationTimeoutSeconds: 180, platformRecoverySeconds: 180 },
    storage: { privateDataDir: '/var/lib/web-agent-bench/private', evidenceDirectory: 'runs', reportRetentionDaysAfterClosure: 30 },
    secretReferences: { authSecretEnv: 'OID_AUTH_SECRET', googleClientSecretEnv: 'OID_GOOGLE_CLIENT_SECRET',
      bonusCodeVerifierSecretEnv: 'OID_BONUS_CODE_VERIFIER_SECRET' },
    clients: [{ family: 'codex', enabled: true, verificationStatus: 'unverified', edition: 'fixture-edition',
      version: 'fixture-version', platform: 'fixture-platform', mcpClientName: 'fixture-mcp-client', mcpClientVersion: '0',
      protocolVersions: ['2025-06-18', '2026-07-28'], authMethods: ['manual_bearer', 'oauth_authorization_code'],
      oauthClientId: 'fixture-oauth-client', redirectUris: ['https://client.example/oauth/callback'],
      verificationEvidenceSha256: [] }, disabled('claude-code'), disabled('claude-desktop'), disabled('hermes')]
  };
}

test('qualification read CIDRs reject unrestricted IPv4 and IPv6 defaults', () => {
  assert.equal(BetaDeploymentManifestSchema.safeParse(qualificationManifest()).success, true);
  for (const cidr of ['0.0.0.0/0', '1.2.3.4/0', '::/0', '2001:db8::1/0']) {
    assert.equal(BetaDeploymentManifestSchema.safeParse(qualificationManifest([cidr])).success, false, cidr);
  }
});

test('socket-peer allowlist matching handles IPv4, IPv6 and mapped IPv4 without forwarded headers', () => {
  assert.equal(isAddressInCidrs('203.0.113.22', ['203.0.113.0/24']), true);
  assert.equal(isAddressInCidrs('203.0.114.22', ['203.0.113.0/24']), false);
  assert.equal(isAddressInCidrs('2001:db8:1::9', ['2001:db8:1::/48']), true);
  assert.equal(isAddressInCidrs('2001:db8:2::9', ['2001:db8:1::/48']), false);
  assert.equal(isAddressInCidrs('::ffff:203.0.113.22', ['203.0.113.0/24']), true);
  assert.equal(isAddressInCidrs(undefined, ['0.0.0.0/0']), false);
});

test('qualification gates direct socket peers and rejects a shared trusted proxy peer', () => {
  const manifest = BetaDeploymentManifestSchema.parse(qualificationManifest());
  assert.equal(isQualificationReadPeerAllowed('203.0.113.22', manifest), true);
  // Even if X-Forwarded-For claims an allowlisted source, a public caller relayed by this
  // shared proxy is indistinguishable at the app and therefore cannot pass this gate.
  assert.equal(isQualificationReadPeerAllowed('192.0.2.10', manifest), false);
  assert.equal(isQualificationReadPeerAllowed('203.0.114.22', manifest), false);
});

test('beta MCP transport accepts only the enabled pinned client and protocol', () => {
  const manifest = BetaDeploymentManifestSchema.parse(qualificationManifest());
  const config = { ...loadConfig({ OID_DATABASE_URL: 'postgres://test.invalid/local',
    OID_AUTH_SECRET: 'test-only-placeholder-not-a-real-secret-value' }),
    betaManifest: manifest, mcpTransportProfile: 'beta-remote-v1' as const, nodeEnv: 'production', mcpClientRegistry: [] };
  const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-06-18', clientInfo: { name: 'fixture-mcp-client', version: '0' }
  } };
  const streamableHeaders = { accept: 'application/json, text/event-stream' };
  assert.equal(selectAgentMcpTransport(config, true, initialize, { ...streamableHeaders,
    'mcp-protocol-version': '2025-06-18' }), 'beta-remote');
  assert.equal(selectAgentMcpTransport(config, true, { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }), 'beta-remote');
  const modernCall = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'identity.preflight', arguments: {} },
    _meta: { 'io.modelcontextprotocol/clientInfo': { name: 'fixture-mcp-client', version: '0' } } };
  assert.equal(selectAgentMcpTransport(config, true, modernCall, { ...streamableHeaders,
    'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'identity.preflight' }), 'beta-remote');
  assert.throws(() => selectAgentMcpTransport(config, true, modernCall, { ...streamableHeaders,
    'mcp-protocol-version': '2026-07-28', 'mcp-name': 'identity.preflight' }), /routing headers/);
  assert.throws(() => selectAgentMcpTransport(config, true, modernCall, { ...streamableHeaders,
    'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'other' }), /routing headers/);
  assert.throws(() => selectAgentMcpTransport(config, true, { ...initialize,
    params: { ...initialize.params, clientInfo: { name: 'unlisted-client', version: '0' } }
  }, { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }), /not in the pinned beta profile/);
  assert.throws(() => selectAgentMcpTransport(config, true, { ...initialize,
    params: { ...initialize.params, clientInfo: { name: 'fixture-mcp-client', version: '1' } }
  }, { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }), /not in the pinned beta profile/);
  assert.throws(() => selectAgentMcpTransport(config, true, { ...initialize,
    params: { ...initialize.params, protocolVersion: '2026-07-28' }
  }, { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }), /do not match/);
  assert.equal(selectAgentMcpTransport(config, false, initialize,
    { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }, 'fixture-oauth-client'), 'beta-remote');
  assert.throws(() => selectAgentMcpTransport(config, false, initialize,
    { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }, 'unlisted-oauth-client'), /not in the pinned beta profile/);
  assert.throws(() => selectAgentMcpTransport(config, false, initialize,
    { ...streamableHeaders, 'mcp-protocol-version': '2025-06-18' }), /not in the pinned beta profile/);
  assert.throws(() => selectAgentMcpTransport(config, true, initialize,
    { accept: 'application/json', 'mcp-protocol-version': '2025-06-18' }), /Streamable HTTP/);
});
