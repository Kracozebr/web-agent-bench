import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';
import {
  EnvironmentAdvisoryLockTimeout,
  poolFor,
  withEnvironmentAdvisoryLock,
} from './db.js';

const lockTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;

test('advisory lock waiters do not starve nested pool queries with more than twelve contenders', {
  skip: !lockTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local PostgreSQL test database.' : false,
}, async () => {
  assert.ok(lockTestUrl);
  const url = new URL(lockTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.match(url.pathname, /(?:bef[-_])?migration[-_]?test/i);
  const pool = poolFor(lockTestUrl);
  const envId = `bef-lock-${randomUUID()}`;
  try {
    await Promise.all(Array.from({ length: 20 }, (_, worker) => withEnvironmentAdvisoryLock(
      pool,
      envId,
      async () => {
        const nested = await pool.query<{ worker: number }>('SELECT $1::integer AS worker', [worker]);
        assert.equal(nested.rows[0]?.worker, worker);
        await new Promise<void>((resolve) => setTimeout(resolve, 40));
      },
      10_000,
    )));
  } finally {
    await pool.end();
  }
});

test('uncertain advisory query result discards its client and never invokes the callback', async () => {
  const released: Array<Error | undefined> = [];
  let callbackEntered = false;
  const fakePool = {
    connect: async () => ({
      query: async () => { throw new Error('simulated_lost_lock_response'); },
      release: (error?: Error) => { released.push(error); },
    }),
  } as unknown as pg.Pool;
  await assert.rejects(
    withEnvironmentAdvisoryLock(fakePool, 'bef-lock-fault', async () => { callbackEntered = true; }),
    /simulated_lost_lock_response/,
  );
  assert.equal(callbackEntered, false);
  assert.equal(released.length, 1);
  assert.match(released[0]?.message ?? '', /simulated_lost_lock_response/);
});

test('a client checked out after the lock deadline is released without running the callback', async () => {
  let releaseCount = 0;
  let callbackEntered = false;
  const fakePool = {
    connect: async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 30));
      return { query: async () => ({ rows: [{ acquired: true }] }), release: () => { releaseCount += 1; } };
    },
  } as unknown as pg.Pool;
  await assert.rejects(
    withEnvironmentAdvisoryLock(fakePool, 'bef-lock-late', async () => { callbackEntered = true; }, 1),
    EnvironmentAdvisoryLockTimeout,
  );
  await new Promise<void>((resolve) => setTimeout(resolve, 40));
  assert.equal(callbackEntered, false);
  assert.equal(releaseCount, 1);
});