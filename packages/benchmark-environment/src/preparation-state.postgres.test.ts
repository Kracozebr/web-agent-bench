import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import {
  bindFixtureTransactionHash,
  bindPreparationGeneration,
  confirmPreparationFence,
  markPreparationUnknown,
  PreparationResponseStore,
  preparationRequestHash,
  publicPreparationStatus,
  recordPreparationFixture,
  recordPreparationResetProof,
  reservePreparation,
  selectPreparation,
  withPgTransaction,
  type PreparationRequestPins,
} from './preparation-state.js';
import { poolFor, ensureSchema } from './db.js';
import { withEnvironmentAdvisoryLock } from './db.js';
import { registerPreparationRoutes } from './preparation-routes.js';
import { EphemeralSignerStore } from './ephemeral-signer-store.js';
import { fenceProcessLostGenerations, type ApplicationRuntime } from './runtime.js';

const databaseUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;

test('preparation identity is globally unique, fenced before creation, and never stores replay secrets', {
  skip: !databaseUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to an isolated local PostgreSQL test database.' : false,
}, async () => {
  assert.ok(databaseUrl);
  const url = new URL(databaseUrl);
  assert.ok(['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase()));
  assert.match(decodeURIComponent(url.pathname.replace(/^\/+/, '')), /^bef_migration_test_[a-z0-9_]+$/i);

  const pool = poolFor(databaseUrl);
  const nonce = randomUUID().replaceAll('-', '');
  const envId = `prep-${nonce.slice(0, 20)}`;
  const otherEnvId = `prep-other-${nonce.slice(0, 16)}`;
  const manifestSha256 = 'a'.repeat(64);
  const tombstoneId = randomUUID();
  const preparationId = randomUUID();
  const generationId = randomUUID();
  const payerAddress = '0x1111111111111111111111111111111111111111';
  const transactionHash = `0x${'ab'.repeat(32)}`;
  const pins: PreparationRequestPins = {
    preparationId,
    envId,
    publicPinsSha256: 'f'.repeat(64),
    participantId: 'participant-preparation-test',
    payerAddress,
    resourceVariant: 'canonical',
    manifestSha256,
  };
  const runToken = 'test-only-run-token-not-persisted';

  try {
    await ensureSchema(pool);
    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES ($1,8453,'private-anvil-fork',$3),($2,8453,'private-anvil-fork',$3)`,
      [envId, otherEnvId, manifestSha256],
    );

    await withEnvironmentAdvisoryLock(pool, envId, async () => {
      const tombstone = await withPgTransaction(pool, (client) => confirmPreparationFence(client, {
        preparationId: tombstoneId,
        envId,
      }));
      assert.equal(tombstone.kind, 'fenced');
      if (tombstone.kind !== 'fenced') throw new Error('expected fenced tombstone');
      assert.equal(tombstone.record.generation_id, null);
      assert.equal(tombstone.record.status, 'fenced');
      assert.ok(tombstone.record.fence_confirmed_at);

      const lateCreate = await withPgTransaction(pool, (client) => reservePreparation(client, {
        ...pins,
        preparationId: tombstoneId,
      }));
      assert.equal(lateCreate, 'preparation_id_used');
    });

    await withEnvironmentAdvisoryLock(pool, envId, async () => {
      const created = await withPgTransaction(pool, (client) => reservePreparation(client, pins));
      assert.equal(created, 'created');
      const reserved = await withPgTransaction(pool, (client) => selectPreparation(client, preparationId, envId));
      assert.ok(reserved);
      assert.equal(reserved.status, 'preparing');
      assert.equal(reserved.generation_id, null);
      assert.equal(reserved.request_sha256?.trim(), preparationRequestHash(pins));

      const crossEnvironmentReuse = await withPgTransaction(pool, (client) => reservePreparation(client, {
        ...pins,
        envId: otherEnvId,
      }));
      assert.equal(crossEnvironmentReuse, 'preparation_id_used');

      await assert.rejects(() => bindPreparationGeneration(pool, {
        pins,
        generationId,
        runTokenSha256: 'c'.repeat(64),
        expiresAt: new Date(Date.now() + 60_000),
      }), /preparation_generation_reservation_not_available/);

      await recordPreparationResetProof(pool, {
        preparationId,
        envId,
        resetIdentity: { chainId: '0x2105', forkBlockHash: `0x${'cd'.repeat(32)}`, facilitatorRecovered: true },
      });
      await bindPreparationGeneration(pool, {
        pins,
        generationId,
        runTokenSha256: 'c'.repeat(64),
        expiresAt: new Date(Date.now() + 60_000),
      });
      await bindFixtureTransactionHash(pool, { preparationId, envId, generationId, transactionHash });

      const bound = await withPgTransaction(pool, (client) => selectPreparation(client, preparationId, envId));
      assert.ok(bound);
      assert.equal(bound.generation_id, generationId);
      assert.equal(bound.fixture_state, 'hash_bound');
      assert.equal(bound.fixture_transaction_hash, transactionHash);
      assert.equal(JSON.stringify(publicPreparationStatus(bound)).includes(runToken), false);
      assert.equal(JSON.stringify(publicPreparationStatus(bound)).includes('run_token_sha256'), false);

      await assert.rejects(() => pool.query(
        `UPDATE bef_preparation SET generation_id=$3 WHERE preparation_id=$1 AND env_id=$2`,
        [preparationId, envId, randomUUID()],
      ), /preparation identity is immutable/);
      await assert.rejects(() => pool.query(
        `DELETE FROM bef_preparation WHERE preparation_id=$1`, [preparationId],
      ), /preparation identities are append-only/);

      await markPreparationUnknown(pool, { preparationId, envId });
      const fence = await withPgTransaction(pool, (client) => confirmPreparationFence(client, { preparationId, envId }));
      assert.equal(fence.kind, 'fenced');
      if (fence.kind !== 'fenced') throw new Error('expected preparation fence');
      assert.equal(fence.record.status, 'fenced');
      assert.equal(fence.record.generation_id, generationId);
      assert.equal(fence.record.fixture_transaction_hash, transactionHash);
      assert.equal(fence.record.fixture_state, 'unknown');
      const generation = await pool.query<{ status: string }>(
        `SELECT status FROM bef_generation WHERE env_id=$1 AND generation_id=$2`, [envId, generationId],
      );
      assert.equal(generation.rows[0]?.status, 'fenced');

      await assert.rejects(() => pool.query(
        `UPDATE bef_preparation SET status='ready',fixture_state='observed',fixture_block_hash=$3,
               fixture_hash=$4,fixture_facts='{}'::jsonb WHERE preparation_id=$1 AND env_id=$2`,
        [preparationId, envId, `0x${'de'.repeat(32)}`, 'e'.repeat(64)],
      ), /preparation status cannot move backwards/);
    });

    const responseCache = new PreparationResponseStore();
    const response = {
      envId,
      preparationId,
      generationId,
      participantId: pins.participantId,
      payerAddress,
      runToken,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      fixture: {
        transactionHash,
        blockHash: `0x${'de'.repeat(32)}`,
        amountUnits: '1',
        payerTokenBefore: '0',
        payerTokenAfter: '1',
        donorTokenBefore: '2',
        donorTokenAfter: '1',
        payerNativeBalance: '3',
        receiptObservation: {},
      },
    };
    responseCache.put(preparationRequestHash(pins), response, Date.parse(response.expiresAt));
    assert.deepEqual(responseCache.get(envId, preparationId, preparationRequestHash(pins)), response);
    assert.equal(new PreparationResponseStore().get(envId, preparationId, preparationRequestHash(pins)), null);
    responseCache.erasePreparation(envId, preparationId);
    assert.equal(responseCache.get(envId, preparationId, preparationRequestHash(pins)), null);
  } finally {
    // Preparation rows are append-only; fail-safe cleanup fences any row created by this test.
    await pool.query(
      `UPDATE bef_generation SET status='fenced',fenced_at=COALESCE(fenced_at,clock_timestamp())
        WHERE env_id=$1 AND generation_id=$2 AND status='active'`,
      [envId, generationId],
    ).catch(() => undefined);
    await pool.query(
      `UPDATE bef_preparation SET status='fenced',fence_confirmed_at=COALESCE(fence_confirmed_at,clock_timestamp())
        WHERE preparation_id=ANY($1::uuid[]) AND env_id=$2 AND status <> 'fenced'`,
      [[tombstoneId, preparationId], envId],
    ).catch(() => undefined);
    await pool.end();
  }
});

test('preparation HTTP fence tombstone blocks late creation and exposes only public status', {
  skip: !databaseUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to an isolated local PostgreSQL test database.' : false,
}, async (t) => {
  assert.ok(databaseUrl);
  const pool = poolFor(databaseUrl);
  const envId = `prep-http-${randomUUID().replaceAll('-', '').slice(0, 18)}`;
  const preparationId = randomUUID();
  const manifestSha256 = 'b'.repeat(64);
  await ensureSchema(pool);
  await pool.query(
    `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
     VALUES ($1,8453,'private-anvil-fork',$2)`,
    [envId, manifestSha256],
  );
  const app: FastifyInstance = Fastify({ logger: false });
  const runtime = {
    config: { adminKey: 'test-admin-key', serviceKey: 'test-service-key' },
    envs: new Map([[envId, {
      id: envId,
      facilitatorAddress: '0x0000000000000000000000000000000000000002',
    }]]),
    pool,
    loadedManifest: { sha256: manifestSha256 },
    manifest: {
      guardrails: { maxTrialSeconds: 300 },
      funding: {
        donor: '0x0000000000000000000000000000000000000001',
        facilitatorNativeEthWei: '1',
      },
    },
    preparationResponses: new PreparationResponseStore(),
    signerStore: new EphemeralSignerStore(),
  } as unknown as ApplicationRuntime;
  registerPreparationRoutes(app, runtime);
  t.after(async () => {
    await app.close();
    await pool.end();
  });

  const baseUrl = `/internal/admin/environments/${envId}/preparations/${preparationId}`;
  const fence = await app.inject({
    method: 'POST',
    url: `${baseUrl}/fence`,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
    payload: {},
  });
  assert.equal(fence.statusCode, 200);
  assert.equal(fence.json().fenceConfirmed, true);
  assert.equal(fence.json().generationId, null);

  const status = await app.inject({
    method: 'GET',
    url: baseUrl,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
  });
  assert.equal(status.statusCode, 200);
  assert.equal(status.json().status, 'fenced');
  assert.equal(status.json().generationId, null);
  assert.equal(status.json().runToken, undefined);
  assert.equal(status.json().signer, undefined);

  const latePrepare = await app.inject({
    method: 'PUT',
    url: baseUrl,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
    payload: {
      publicPinsSha256: 'f'.repeat(64),
      participantId: 'participant-http-test',
      payerAddress: '0x1111111111111111111111111111111111111111',
      resourceVariant: 'canonical',
    },
  });
  assert.equal(latePrepare.statusCode, 409);
  assert.deepEqual(latePrepare.json(), { error: 'preparation_identity_conflict' });
});

test('preparation PUT replays only the matching public pin and restart fences its RAM-only response', {
  skip: !databaseUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to an isolated local PostgreSQL test database.' : false,
}, async (t) => {
  assert.ok(databaseUrl);
  const pool = poolFor(databaseUrl);
  const app: FastifyInstance = Fastify({ logger: false });
  t.after(async () => {
    await app.close();
    await pool.end();
  });
  const envId = `prep-replay-${randomUUID().replaceAll('-', '').slice(0, 16)}`;
  const preparationId = randomUUID();
  const generationId = randomUUID();
  const manifestSha256 = 'c'.repeat(64);
  const publicPinsSha256 = 'f'.repeat(64);
  const payerAddress = '0x1111111111111111111111111111111111111111';
  const transactionHash = `0x${'ab'.repeat(32)}`;
  const blockHash = `0x${'de'.repeat(32)}`;
  const runTokenSha256 = '9'.repeat(64);
  const runToken = 'clear-test-run-token-in-memory-only';
  const pins: PreparationRequestPins = {
    preparationId,
    envId,
    publicPinsSha256,
    participantId: 'participant-preparation-replay',
    payerAddress,
    resourceVariant: 'canonical',
    manifestSha256,
  };
  const expiresAt = new Date(Date.now() + 300_000).toISOString();
  await ensureSchema(pool);
  await pool.query(
    `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
     VALUES ($1,8453,'private-anvil-fork',$2)`,
    [envId, manifestSha256],
  );
  try {
    await withEnvironmentAdvisoryLock(pool, envId, async () => {
      assert.equal(await withPgTransaction(pool, (client) => reservePreparation(client, pins)), 'created');
      await recordPreparationResetProof(pool, {
        preparationId,
        envId,
        resetIdentity: { chainId: '0x2105', forkBlockHash: `0x${'cd'.repeat(32)}`, facilitatorRecovered: true },
      });
      await bindPreparationGeneration(pool, {
        pins,
        generationId,
        runTokenSha256,
        expiresAt: new Date(expiresAt),
      });
      await bindFixtureTransactionHash(pool, { preparationId, envId, generationId, transactionHash });
      await recordPreparationFixture(pool, {
        preparationId,
        envId,
        generationId,
        participantId: pins.participantId,
        fixture: {
          transactionHash,
          blockHash,
          amountUnits: '100000',
          payerTokenBefore: '0',
          payerTokenAfter: '100000',
          donorTokenBefore: '200000',
          donorTokenAfter: '100000',
          payerNativeBalance: '100000000000000000',
          receiptObservation: { pollCount: 1, nullReceiptCount: 0 },
          fixtureHash: '8'.repeat(64),
        },
        expiresAtSeconds: 300,
      });
    });

    const preparationResponses = new PreparationResponseStore();
    const response = {
      envId,
      preparationId,
      generationId,
      participantId: pins.participantId,
      payerAddress,
      runToken,
      expiresAt,
      fixture: {
        transactionHash,
        blockHash,
        amountUnits: '100000',
        payerTokenBefore: '0',
        payerTokenAfter: '100000',
        donorTokenBefore: '200000',
        donorTokenAfter: '100000',
        payerNativeBalance: '100000000000000000',
        receiptObservation: { pollCount: 1, nullReceiptCount: 0 },
      },
    };
    preparationResponses.put(preparationRequestHash(pins), response, Date.parse(expiresAt));
    const runtime = {
      config: { adminKey: 'test-admin-key', serviceKey: 'test-service-key' },
      envs: new Map([[envId, { id: envId, facilitatorAddress: '0x0000000000000000000000000000000000000002' }]]),
      pool,
      loadedManifest: { sha256: manifestSha256 },
      manifest: {
        guardrails: { maxTrialSeconds: 300 },
        funding: {
          donor: '0x0000000000000000000000000000000000000001',
          facilitatorNativeEthWei: '1',
        },
      },
      preparationResponses,
      signerStore: new EphemeralSignerStore(),
    } as unknown as ApplicationRuntime;
    registerPreparationRoutes(app, runtime);

    const url = `/internal/admin/environments/${envId}/preparations/${preparationId}`;
    const payload = {
      publicPinsSha256,
      participantId: pins.participantId,
      payerAddress,
      resourceVariant: pins.resourceVariant,
    };
    const replay = await app.inject({
      method: 'PUT', url, headers: { 'x-bef-admin-key': 'test-admin-key' }, payload,
    });
    assert.equal(replay.statusCode, 201);
    assert.equal(replay.json().runToken, runToken);
    assert.equal(replay.json().generationId, generationId);

    const changedPins = await app.inject({
      method: 'PUT', url, headers: { 'x-bef-admin-key': 'test-admin-key' },
      payload: { ...payload, publicPinsSha256: 'e'.repeat(64) },
    });
    assert.equal(changedPins.statusCode, 409);
    assert.deepEqual(changedPins.json(), { error: 'preparation_identity_conflict' });

    const status = await app.inject({ method: 'GET', url, headers: { 'x-bef-admin-key': 'test-admin-key' } });
    assert.equal(status.statusCode, 200);
    assert.equal(status.json().status, 'ready');
    assert.equal(status.json().runToken, undefined);
    assert.equal(status.json().signer, undefined);
    assert.equal(JSON.stringify(status.json()).includes(runToken), false);
    assert.equal(JSON.stringify(status.json()).includes(runTokenSha256), false);
    const storedPreparation = await pool.query<{ serialized: string }>(
      `SELECT to_jsonb(p)::text AS serialized FROM bef_preparation p WHERE preparation_id=$1`, [preparationId],
    );
    assert.equal(storedPreparation.rows[0]?.serialized.includes(runToken), false);
    assert.equal(storedPreparation.rows[0]?.serialized.includes(runTokenSha256), false);

    // A fresh process has no response cache and therefore cannot recover the bearer token.
    runtime.preparationResponses = new PreparationResponseStore();
    const lostResponse = await app.inject({
      method: 'PUT', url, headers: { 'x-bef-admin-key': 'test-admin-key' }, payload,
    });
    assert.equal(lostResponse.statusCode, 409);
    assert.equal(lostResponse.json().error, 'preparation_secret_unavailable');

    await fenceProcessLostGenerations(pool, [envId]);
    const fencedStatus = await app.inject({ method: 'GET', url, headers: { 'x-bef-admin-key': 'test-admin-key' } });
    assert.equal(fencedStatus.statusCode, 200);
    assert.equal(fencedStatus.json().status, 'fenced');
    assert.equal(fencedStatus.json().generationId, generationId);
    assert.equal(fencedStatus.json().fixture.transactionHash, transactionHash);
    const fencedReplay = await app.inject({
      method: 'PUT', url, headers: { 'x-bef-admin-key': 'test-admin-key' }, payload,
    });
    assert.equal(fencedReplay.statusCode, 409);
    assert.equal(fencedReplay.json().error, 'preparation_not_replayable');
  } finally {
    await pool.query(
      `UPDATE bef_generation SET status='fenced',fenced_at=COALESCE(fenced_at,clock_timestamp())
        WHERE env_id=$1 AND generation_id=$2 AND status='active'`,
      [envId, generationId],
    ).catch(() => undefined);
    await pool.query(
      `UPDATE bef_preparation SET status='fenced',fence_confirmed_at=COALESCE(fence_confirmed_at,clock_timestamp())
        WHERE preparation_id=$1 AND env_id=$2 AND status <> 'fenced'`,
      [preparationId, envId],
    ).catch(() => undefined);
  }
});

test('preparation PUT refuses a new fork reset while an environment is active or unresolved', {
  skip: !databaseUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to an isolated local PostgreSQL test database.' : false,
}, async (t) => {
  assert.ok(databaseUrl);
  const pool = poolFor(databaseUrl);
  const app: FastifyInstance = Fastify({ logger: false });
  t.after(async () => {
    await app.close();
    await pool.end();
  });
  const envId = `prep-gate-${randomUUID().replaceAll('-', '').slice(0, 16)}`;
  const manifestSha256 = 'a'.repeat(64);
  const activePreparationId = randomUUID();
  const unresolvedPreparationId = randomUUID();
  const generationId = randomUUID();
  const operationId = randomUUID();
  const payerAddress = '0x1111111111111111111111111111111111111111';
  await ensureSchema(pool);
  await pool.query(
    `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
     VALUES ($1,8453,'private-anvil-fork',$2)`,
    [envId, manifestSha256],
  );
  const runtime = {
    config: { adminKey: 'test-admin-key', serviceKey: 'test-service-key' },
    envs: new Map([[envId, { id: envId, facilitatorAddress: '0x0000000000000000000000000000000000000002' }]]),
    pool,
    loadedManifest: { sha256: manifestSha256 },
    manifest: {
      guardrails: { maxTrialSeconds: 300 },
      funding: {
        donor: '0x0000000000000000000000000000000000000001',
        facilitatorNativeEthWei: '1',
      },
    },
    preparationResponses: new PreparationResponseStore(),
    signerStore: new EphemeralSignerStore(),
  } as unknown as ApplicationRuntime;
  registerPreparationRoutes(app, runtime);
  const payload = {
    publicPinsSha256: 'f'.repeat(64),
    participantId: 'participant-preparation-gate',
    payerAddress,
    resourceVariant: 'canonical',
  };

  await pool.query(
    `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,
       resource_variant,manifest_sha256,status,expires_at)
     VALUES($1,$2,'active-preparation-test',$3,$4,'canonical',$5,'active',clock_timestamp()+interval '5 minutes')`,
    [generationId, envId, 'c'.repeat(64), payerAddress, manifestSha256],
  );
  const activeResponse = await app.inject({
    method: 'PUT',
    url: `/internal/admin/environments/${envId}/preparations/${activePreparationId}`,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
    payload,
  });
  assert.equal(activeResponse.statusCode, 409);
  assert.deepEqual(activeResponse.json(), { error: 'active_generation_requires_fence' });
  const noActiveReservation = await pool.query(
    `SELECT 1 FROM bef_preparation WHERE preparation_id=$1`, [activePreparationId],
  );
  assert.equal(noActiveReservation.rowCount, 0);

  await pool.query(
    `UPDATE bef_generation SET status='fenced',fenced_at=clock_timestamp()
      WHERE env_id=$1 AND generation_id=$2 AND status='active'`, [envId, generationId],
  );
  await pool.query(
    `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,
       request_sha256,operation_kind,status,transaction_hash,receipt_status)
     VALUES($1,$2,$3,'unresolved-preparation-test',$4,$5,'purchase','settlement_unknown',$6,'unknown')`,
    [operationId, envId, generationId, '1'.repeat(64), '2'.repeat(64), `0x${'ab'.repeat(32)}`],
  );
  const unresolvedResponse = await app.inject({
    method: 'PUT',
    url: `/internal/admin/environments/${envId}/preparations/${unresolvedPreparationId}`,
    headers: { 'x-bef-admin-key': 'test-admin-key' },
    payload,
  });
  assert.equal(unresolvedResponse.statusCode, 409);
  assert.deepEqual(unresolvedResponse.json(), { error: 'unresolved_operation_blocks_preparation' });
  const noUnresolvedReservation = await pool.query(
    `SELECT 1 FROM bef_preparation WHERE preparation_id=$1`, [unresolvedPreparationId],
  );
  assert.equal(noUnresolvedReservation.rowCount, 0);
});
