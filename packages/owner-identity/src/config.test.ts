import assert from 'node:assert/strict';
import test from 'node:test';
import { join } from 'node:path';
import { isPathOutsideDirectory, isPathWithinDirectory, loadConfig } from './config.js';

const baseEnv: NodeJS.ProcessEnv = {
  OID_DATABASE_URL: 'postgres://test.invalid/owner_identity',
  OID_AUTH_SECRET: 'test-only-placeholder-not-a-real-secret-value',
};

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
