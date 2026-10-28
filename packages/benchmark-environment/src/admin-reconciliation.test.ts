import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import type { ApplicationRuntime } from './runtime.js';
import { registerAdminRoutes } from './admin-routes.js';
import type { PostgresExecutionPersistence } from './selected-execution-persistence.js';

const operationId = '31b0b927-79f7-4e07-87e3-f5ed2f9c97e6';

function appForAdminRoute(): FastifyInstance {
  const app = Fastify({ logger: false });
  const runtime = {
    config: { adminKey: 'test-admin-key' },
    envs: new Map([['bef-a', { id: 'bef-a' }]]),
  } as unknown as ApplicationRuntime;
  registerAdminRoutes(app, runtime, {} as PostgresExecutionPersistence);
  return app;
}

test('selected-execution reconciliation requires the configured admin key', async (t) => {
  const app = appForAdminRoute();
  t.after(() => app.close());
  const response = await app.inject({
    method: 'POST',
    url: `/internal/admin/environments/bef-a/selected-executions/${operationId}/reconcile`,
    payload: {},
  });
  assert.equal(response.statusCode, 403);
  assert.deepEqual(response.json(), { error: 'forbidden' });
});

test('selected-execution reconciliation rejects caller-supplied hashes and request fields', async (t) => {
  const app = appForAdminRoute();
  t.after(() => app.close());
  const response = await app.inject({
    method: 'POST',
    url: `/internal/admin/environments/bef-a/selected-executions/${operationId}/reconcile`,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
    payload: { transactionHash: `0x${'ab'.repeat(32)}` },
  });
  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), { error: 'invalid_reconciliation_request' });
});
