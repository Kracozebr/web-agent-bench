import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from './config.js';

const baseEnv: NodeJS.ProcessEnv = {
  OID_DATABASE_URL: 'postgres://test.invalid/owner_identity',
  OID_AUTH_SECRET: 'test-only-placeholder-not-a-real-secret-value',
};

test('local BEF coordinator is disabled by default and requires an explicit private local config', () => {
  assert.equal(loadConfig({ ...baseEnv }).localBefTaskCoordinatorEnabled, false);
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
