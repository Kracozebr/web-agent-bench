import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import Fastify, { type FastifyInstance } from 'fastify';
import { CURRENT_TRAINING_TASK_IDS, PUBLIC_TASK_CATALOG, TASK_IDS, type TaskMode } from './task-catalog.js';
import { registerPublicBenchmarkCatalogRoutes } from './public-benchmark-catalog.js';
import type { RunAdmissionRelease, TaskReleaseProvider } from './task-release.js';

const WEIGHTS = PUBLIC_TASK_CATALOG.map((task) => task.weight);
const RELEASES: Record<TaskMode, RunAdmissionRelease> = {
  ranked: {
    releaseIdentity: 'private-release-id', manifestHash: 'a'.repeat(64), benchmarkVersion: 'bench-v7',
    benchmarkHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), mode: 'ranked', taskIds: TASK_IDS,
    weights: WEIGHTS, priceUnits: '1000000', precision: 6,
  },
  training: {
    releaseIdentity: 'private-release-id', manifestHash: 'a'.repeat(64), benchmarkVersion: 'bench-v7',
    benchmarkHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), mode: 'training', taskIds: CURRENT_TRAINING_TASK_IDS,
    weights: [1, 2, 3], priceUnits: '500000', precision: 6,
  },
};

const apps: FastifyInstance[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

function makeApp(overrides: Partial<TaskReleaseProvider> = {}, resultsConfigured = true) {
  const app = Fastify({ logger: false });
  apps.push(app);
  const provider: TaskReleaseProvider = {
    async getActiveAdmissionRelease(mode) { return RELEASES[mode]; },
    async getValidatedRelease() { return null; },
    getPublicCatalog() { return PUBLIC_TASK_CATALOG; },
    ...overrides,
  };
  registerPublicBenchmarkCatalogRoutes(app, { provider, resultsConfigured });
  return app;
}

test('public catalog returns a safe current version and mode prices only', async () => {
  const app = makeApp();
  const response = await app.inject({ method: 'GET', url: '/api/public/catalog' });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  const body = response.json();
  assert.equal(body.catalogStatus, 'active');
  assert.equal(body.benchmarkVersion, 'bench-v7');
  assert.deepEqual(body.ranked.taskIds, TASK_IDS);
  assert.equal(body.ranked.weights.reduce((sum: number, weight: number) => sum + weight, 0), 26);
  assert.equal(body.ranked.priceUnits, '1000000');
  assert.deepEqual(body.training.taskIds, CURRENT_TRAINING_TASK_IDS);
  assert.equal(body.training.weights.reduce((sum: number, weight: number) => sum + weight, 0), 6);
  assert.equal(body.training.priceUnits, '500000');
  assert.equal(body.tasks.length, 12);
  assert.deepEqual(Object.keys(body.ranked).sort(), ['precision', 'priceUnits', 'taskIds', 'weights']);
  assert.equal(JSON.stringify(body).includes('private-release-id'), false);
  assert.equal(JSON.stringify(body).includes('manifestHash'), false);
  assert.equal(JSON.stringify(body).includes('benchmarkHash'), false);
});

test('missing or inconsistent release metadata does not invent a version or price', async () => {
  const app = makeApp({
    async getActiveAdmissionRelease(mode) {
      if (mode === 'ranked') return null;
      return { ...RELEASES.training, weights: [2, 2, 2] };
    },
  });
  const response = await app.inject({ method: 'GET', url: '/api/public/catalog' });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.catalogStatus, 'unavailable');
  assert.equal('benchmarkVersion' in body, false);
  assert.equal('ranked' in body, false);
  assert.equal('training' in body, false);
  assert.equal(body.tasks.length, 12);
});

test('an edited public rubric projection cannot be paired with an active release', async () => {
  const changedCatalog = PUBLIC_TASK_CATALOG.map((task, index) => index === 0
    ? { ...task, scoringPolicy: 'unreviewed scoring copy' }
    : task);
  const app = makeApp({ getPublicCatalog() { return changedCatalog; } });
  const response = await app.inject({ method: 'GET', url: '/api/public/catalog' });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.catalogStatus, 'unavailable');
  assert.equal('benchmarkVersion' in body, false);
  assert.equal('ranked' in body, false);
  assert.equal('training' in body, false);
});

test('backend failure returns a safe uncached unavailable response', async () => {
  const app = makeApp({
    async getActiveAdmissionRelease() { throw new Error('private-origin-and-query-details'); },
  });
  const response = await app.inject({ method: 'GET', url: '/api/public/catalog' });
  assert.equal(response.statusCode, 503);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.json().error.code, 'PUBLIC_CATALOG_UNAVAILABLE');
  assert.equal(response.body.includes('private-origin-and-query-details'), false);
});

test('public catalog discloses release and results configuration independently', async () => {
  const app = makeApp({}, false);
  const response = await app.inject({ method: 'GET', url: '/api/public/catalog' });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().catalogStatus, 'active');
  assert.equal(response.json().resultsStatus, 'not_configured');
});
