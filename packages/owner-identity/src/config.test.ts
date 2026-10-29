import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isPathOutsideDirectory, isPathWithinDirectory, loadConfig } from './config.js';

const baseEnv: NodeJS.ProcessEnv = {
  OID_DATABASE_URL: 'postgres://test.invalid/owner_identity',
  OID_AUTH_SECRET: 'test-only-placeholder-not-a-real-secret-value',
};

function localGoogleQualificationEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const databaseName = `oid_google_local_${'c'.repeat(32)}`;
  const root = join(process.cwd(), '.local', 'google-qualification', databaseName);
  return { ...baseEnv, NODE_ENV: 'test', OID_DATABASE_URL: `postgres://test.invalid/${databaseName}`,
    OID_PUBLIC_ORIGIN: 'http://127.0.0.1:3000', OID_API_HOST: '127.0.0.1',
    OID_GOOGLE_CLIENT_ID: 'test-google-client-id', OID_GOOGLE_CLIENT_SECRET: 'test-only-not-a-real-google-secret',
    OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true', OID_LOCAL_GOOGLE_QUALIFICATION_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: root, OID_PRIVATE_DATA_DIR: join(root, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(root, 'operator', 'closure.json'),
    ...overrides };
}

function betaQualificationManifest(clientId: string) {
  const hash = 'a'.repeat(64);
  const disabled = (family: string) => ({ family, enabled: false, verificationStatus: 'unverified', edition: null,
    version: null, platform: null, mcpClientName: null, mcpClientVersion: null, protocolVersions: [], authMethods: [],
    oauthClientId: null, redirectUris: [], verificationEvidenceSha256: [] });
  return { schemaVersion: 'beta-deployment-manifest/v1', state: 'qualification', executionProfileId: 'beta-bef-v1',
    transportProfileId: 'beta-remote-v1', source: { commit: 'b'.repeat(40), applicationBuildSha256: hash,
      evaluatorSourceSha256: hash }, publicOrigin: 'https://bench.example', apiBindHost: '127.0.0.1', apiPort: 8784,
    trustedProxyCidrs: ['192.0.2.10/32'], qualificationReadCidrs: ['203.0.113.0/24'],
    google: { issuer: 'https://accounts.google.com', clientId, callbackUri: 'https://bench.example/api/auth/callback/google',
      adminSubject: 'fixture-admin-subject' },
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
      verificationEvidenceSha256: [] }, disabled('claude-code'), disabled('claude-desktop'), disabled('hermes')] };
}

test('beta report closure operator state must resolve outside the private data backup tree', () => {
  const data = join(process.cwd(), '.local', 'owner-identity', 'private-data');
  assert.equal(isPathOutsideDirectory(data, join(data, 'operator', 'beta-report-closure-state.json')), false);
  assert.equal(isPathOutsideDirectory(data, data), false);
  assert.equal(isPathOutsideDirectory(data, join(process.cwd(), '.local', 'owner-identity', 'beta-report-closure-state.json')), true);
  assert.equal(isPathOutsideDirectory(data, undefined), false);
  assert.equal(isPathOutsideDirectory(data, 'operator/beta-report-closure-state.json'), false);
  assert.equal(isPathWithinDirectory(data, join(data, 'operator', 'closure.json')), true);
  assert.equal(isPathWithinDirectory(data, join(process.cwd(), 'outside', 'closure.json')), false);
});

test('local report acceptance is default-off and needs per-capture loopback storage plus external closure state', () => {
  const defaults = loadConfig({ ...baseEnv, NODE_ENV: 'test' });
  assert.equal(defaults.localReportAcceptanceEnabled, false);
  const captureRoot = join(process.cwd(), '.local', 'acceptance', `oid_acceptance_${'a'.repeat(32)}`);
  const enabled = loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_PUBLIC_ORIGIN: 'http://127.0.0.1:3000',
    OID_API_HOST: '127.0.0.1', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'operator', 'beta-report-closure-state.json'),
  });
  assert.equal(enabled.localReportAcceptanceEnabled, true);
  assert.equal(enabled.localGoogleQualificationEnabled, false);
  assert.equal(enabled.localReportCaptureRoot, captureRoot);
  assert.equal(enabled.betaReportClosureStateFile, join(captureRoot, 'operator', 'beta-report-closure-state.json'));
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true' }), /named per-capture loopback runtime/);
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'private-data', 'closure.json'),
  }), /named per-capture loopback runtime/);
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_API_HOST: '0.0.0.0', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'operator', 'closure.json'),
  }), /named per-capture loopback runtime/);
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_PUBLIC_ORIGIN: 'http://acceptance.example',
    OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true', OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'operator', 'closure.json'),
  }), /named per-capture loopback runtime/);
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'production', OID_PUBLIC_ORIGIN: 'https://bench.example',
    OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true', OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'operator', 'closure.json'),
  }), /allowed only in development or test/);
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'test', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: join(process.cwd(), '.local', 'acceptance', 'not-an-acceptance-capture'),
    OID_PRIVATE_DATA_DIR: join(captureRoot, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(captureRoot, 'operator', 'closure.json'),
  }), /named per-capture loopback runtime/);
});

test('local Google qualification requires an explicit development or test report profile bound to its Google database', () => {
  for (const nodeEnv of ['development', 'test']) {
    const enabled = loadConfig(localGoogleQualificationEnv({ NODE_ENV: nodeEnv }));
    assert.equal(enabled.localReportAcceptanceEnabled, true);
    assert.equal(enabled.localGoogleQualificationEnabled, true);
    assert.match(enabled.localReportCaptureRoot ?? '', /oid_google_local_c{32}$/);
  }

  assert.throws(() => loadConfig(localGoogleQualificationEnv({ NODE_ENV: undefined })),
    /requires NODE_ENV=development or test/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'false' })),
    /requires OID_LOCAL_REPORT_ACCEPTANCE_ENABLED=true/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_LOCAL_REPORT_CAPTURE_ROOT:
    join(process.cwd(), '.local', 'google-qualification', `oid_acceptance_${'c'.repeat(32)}`) })),
  /requires an oid_google_local_/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_DATABASE_URL:
    `postgres://test.invalid/oid_google_local_${'d'.repeat(32)}` })), /requires an oid_google_local_/);
});

test('local Google qualification rejects missing or fixture Google credentials and preserves local-only network guards', () => {
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_GOOGLE_CLIENT_ID: undefined,
    OID_GOOGLE_CLIENT_SECRET: undefined })), /requires Google client ID and secret/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_GOOGLE_FIXTURE_ORIGIN: 'http://127.0.0.1:39123' })),
    /requires Google client ID and secret without OID_GOOGLE_FIXTURE_ORIGIN/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ NODE_ENV: 'production' })),
    /requires NODE_ENV=development or test/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_API_HOST: '0.0.0.0' })),
    /named per-capture loopback runtime/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_PUBLIC_ORIGIN: 'http://qualification.example' })),
    /named per-capture loopback runtime/);
  assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_LOCAL_GOOGLE_QUALIFICATION_ENABLED: 'false' })),
    /named per-capture loopback runtime/);
});

test('local Google qualification remains incompatible with a beta manifest', () => {
  const tempRoot = mkdtempSync(join(tmpdir(), 'oid-config-beta-manifest-'));
  const manifestPath = join(tempRoot, 'manifest.json');
  try {
    writeFileSync(manifestPath, JSON.stringify(betaQualificationManifest('test-google-client-id')), { flag: 'wx', mode: 0o600 });
    assert.throws(() => loadConfig(localGoogleQualificationEnv({ OID_BETA_MANIFEST_FILE: manifestPath })),
      /Local report acceptance requires a named per-capture loopback runtime/);
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('isolated restored report fixture binds its database identity and cannot enable an executor', () => {
  const databaseName = `oid_restore_${'b'.repeat(32)}`;
  const root = join(process.cwd(), '.local', 'acceptance', databaseName);
  const env: NodeJS.ProcessEnv = { ...baseEnv, NODE_ENV: 'test',
    OID_DATABASE_URL: `postgres://test.invalid/${databaseName}`,
    OID_PUBLIC_ORIGIN: 'http://127.0.0.1:3000', OID_API_HOST: '127.0.0.1',
    OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true', OID_LOCAL_REPORT_CAPTURE_ROOT: root,
    OID_PRIVATE_DATA_DIR: join(root, 'private-data'),
    OID_BETA_REPORT_CLOSURE_STATE_FILE: join(root, 'operator', 'closure.json') };
  assert.equal(loadConfig(env).localReportCaptureRoot, root);
  assert.throws(() => loadConfig({ ...env, OID_DATABASE_URL: baseEnv.OID_DATABASE_URL }), /named per-capture/);
  assert.throws(() => loadConfig({ ...env, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'true',
    OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG: '.local/owner-identity/worker.json' }), /named per-capture/);
});

test('local BEF coordinator is disabled by default and requires an explicit private local config', () => {
  const defaults = loadConfig({ ...baseEnv });
  assert.equal(defaults.localBefTaskCoordinatorEnabled, false);
  assert.equal(defaults.privateDataDir?.endsWith(join('.local', 'owner-identity', 'private-data')), true);
  assert.throws(() => loadConfig({ ...baseEnv, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'yes' }), /must be true or false/);
  assert.throws(() => loadConfig({ ...baseEnv, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'true' }), /CONFIG is required/);
  const enabled = loadConfig({ ...baseEnv,
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'true',
    OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG: '.local/owner-identity/worker.json',
  });
  assert.equal(enabled.localBefTaskCoordinatorEnabled, true);
  assert.equal(enabled.localBefTaskCoordinatorBatchSize, 10);
  assert.equal(enabled.localBefTaskCoordinatorTickMs, 1000);
});

test('local BEF coordinator rejects production and externally bound API hosts', () => {
  assert.throws(() => loadConfig({ ...baseEnv,
    NODE_ENV: 'production',
    OID_PUBLIC_ORIGIN: 'https://bench.example',
    OID_PRIVATE_DATA_DIR: '/var/lib/web-agent-bench/private',
    OID_MCP_CLIENT_ID: 'owner-local-client',
    OID_MCP_CLIENT_REDIRECT_URI: 'http://127.0.0.1:38765/oauth/callback',
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'true',
    OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG: '.local/owner-identity/worker.json',
  }), /forbidden in production/);
  assert.throws(() => loadConfig({ ...baseEnv,
    OID_API_HOST: '0.0.0.0',
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: 'true',
    OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG: '.local/owner-identity/worker.json',
  }), /loopback OID_API_HOST/);
});

test('Codex transport profile is opt-in and limited to local BEF loopback development', () => {
  const defaults = loadConfig(baseEnv);
  assert.equal(defaults.mcpTransportProfile, 'strict-2026-07-28');
  assert.deepEqual(defaults.mcpClientRegistry, [{ clientId: 'oid-local-mcp-client',
    redirectUris: ['http://127.0.0.1:38765/oauth/callback'], clientName: 'Local MCP Acceptance Client' }]);
  assert.throws(() => loadConfig({...baseEnv, OID_MCP_TRANSPORT_PROFILE:'unknown'}), /supported pinned profile/);
  assert.throws(() => loadConfig({...baseEnv, OID_MCP_TRANSPORT_PROFILE:'codex-local-manual-2025-06-18'}), /requires the local BEF/);
  const local = {...baseEnv, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'true', OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG:'.local/owner-identity/local.json',
    OID_MCP_TRANSPORT_PROFILE:'codex-local-manual-2025-06-18'};
  assert.equal(loadConfig(local).mcpTransportProfile, 'codex-local-manual-2025-06-18');
  assert.throws(() => loadConfig({...local, OID_PUBLIC_ORIGIN:'http://external.example'}), /loopback HTTP origin/);
});

test('production continues to reject provider fixtures', () => {
  assert.throws(() => loadConfig({ ...baseEnv, NODE_ENV: 'production', OID_PUBLIC_ORIGIN: 'https://bench.example',
    OID_PRIVATE_DATA_DIR: '/var/lib/web-agent-bench/private', OID_MCP_CLIENT_ID: 'owner-local-client',
    OID_MCP_CLIENT_REDIRECT_URI: 'http://127.0.0.1:38765/oauth/callback',
    OID_GOOGLE_FIXTURE_ORIGIN: 'https://google-fixture.example' }), /forbidden in production/);
});
