import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { ensureSchema, poolFor, verifySchema } from './db.js';
import { recordPrivateVerificationStarted } from './facilitator-verification.js';

const migrationTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;
const REQUEST_HASH = 'a'.repeat(64);
const MANIFEST_HASH = 'b'.repeat(64);
const PAYER = '0x1111111111111111111111111111111111111111';
const OFFER = { id: 'canonical', amount: '100000' };

test('PostgreSQL SC005 verify-only recording preserves awaiting_payment and is generation scoped', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated loopback migration-test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['127.0.0.1', 'localhost', '::1', '[::1]'].includes(url.hostname.toLowerCase()),
    'the migration-test database must be loopback-only');
  const databaseName = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  assert.match(databaseName, /^bef_migration_test(?:_[a-z0-9]+)*$/i,
    'the test URL must target a dedicated bef_migration_test database');

  const pool = poolFor(migrationTestUrl);
  const nonce = randomUUID().replaceAll('-', '');
  const envs = [
    `bef-vfy-${nonce.slice(0, 16)}-private`,
    `bef-vfy-${nonce.slice(0, 16)}-negative`,
    `bef-vfy-${nonce.slice(0, 16)}-canonical`,
    `bef-vfy-${nonce.slice(0, 16)}-terminal`,
  ];
  const generations = envs.map(() => randomUUID());
  const operations = Array.from({ length: 5 }, () => randomUUID());

  const createCase = async (
    index: number,
    resourceVariant: 'verification_without_receipt' | 'canonical',
    options: { selected?: boolean; operationStatus?: string; generationStatus?: 'active' | 'fenced' } = {},
  ) => {
    const envId = envs[index]!;
    const generationId = generations[index]!;
    const operationId = operations[index]!;
    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES($1,8453,'private-anvil-fork',$2)`, [envId, MANIFEST_HASH],
    );
    await pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,
         resource_variant,manifest_sha256,status,expires_at)
       VALUES($1,$2,'sc005-verification-test',$3,$4,$5,$6,$7,clock_timestamp()+interval '1 hour')`,
      [generationId, envId, nonce.repeat(2).slice(0, 64), PAYER, resourceVariant, MANIFEST_HASH, options.generationStatus ?? 'active'],
    );
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,
         request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'sc005-verification-test',$4,$5,'purchase','awaiting_payment',true)`,
      [operationId, envId, generationId, operationId.replaceAll('-', '').repeat(2), REQUEST_HASH],
    );
    if (options.selected) {
      await pool.query(
        `UPDATE bef_operation SET selected_offer_id=$2,selected_amount_units=$3,
                offer_selected_at=clock_timestamp(),offer_selection_eligible=false
          WHERE operation_id=$1`, [operationId, OFFER.id, OFFER.amount],
      );
    }
    if (options.operationStatus && options.operationStatus !== 'awaiting_payment') {
      await pool.query('UPDATE bef_operation SET status=$2 WHERE operation_id=$1', [operationId, options.operationStatus]);
    }
    return { envId, generationId, operationId, requestSha256: REQUEST_HASH };
  };

  try {
    await ensureSchema(pool);
    await verifySchema(pool);
    const actualDatabase = await pool.query<{ current_database: string }>('SELECT current_database()');
    assert.equal(actualDatabase.rows[0]?.current_database, databaseName);

    const valid = await createCase(0, 'verification_without_receipt', { selected: true });
    assert.equal(await recordPrivateVerificationStarted(pool, valid, OFFER), true);
    const persisted = await pool.query<{
      status: string;
      offer_selected_at: Date;
      verification_started_at: Date | null;
      selection_precedes_verification: boolean;
    }>(
      `SELECT status,offer_selected_at,verification_started_at,
              verification_started_at >= offer_selected_at AS selection_precedes_verification
         FROM bef_operation WHERE operation_id=$1`, [valid.operationId],
    );
    assert.equal(persisted.rows[0]?.status, 'awaiting_payment');
    assert.ok(persisted.rows[0]?.verification_started_at instanceof Date);
    assert.equal(persisted.rows[0]?.selection_precedes_verification, true);
    assert.equal(await recordPrivateVerificationStarted(pool, valid, OFFER), true, 'the exact verify request is idempotent');
    const payments = await pool.query('SELECT 1 FROM bef_payment WHERE operation_id=$1', [valid.operationId]);
    assert.equal(payments.rowCount, 0, 'verification-only recording creates no payment');

    const wrongHash = await createCase(1, 'verification_without_receipt', { selected: true });
    assert.equal(await recordPrivateVerificationStarted(pool, { ...wrongHash, requestSha256: 'c'.repeat(64) }, OFFER), false);
    const unselected = { ...wrongHash, operationId: operations[4]! };
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,
         request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'sc005-verification-test',$4,$5,'purchase','awaiting_payment',true)`,
      [unselected.operationId, unselected.envId, unselected.generationId,
        unselected.operationId.replaceAll('-', '').repeat(2), REQUEST_HASH],
    );
    assert.equal(await recordPrivateVerificationStarted(pool, unselected, OFFER), false);
    assert.equal(await recordPrivateVerificationStarted(pool, wrongHash, { id: 'task-goal-exceeded', amount: '3000000' }), false,
      'a caller offer that differs from the persisted pinned choice cannot start verification');

    const nonPrivate = await createCase(2, 'canonical', { selected: true });
    assert.equal(await recordPrivateVerificationStarted(pool, nonPrivate, OFFER), false);

    const terminal = await createCase(3, 'verification_without_receipt', { selected: true, operationStatus: 'rejected' });
    assert.equal(await recordPrivateVerificationStarted(pool, terminal, OFFER), false);

    const fencedEnv = `bef-vfy-${nonce.slice(16, 32)}-fenced`;
    const fencedGeneration = randomUUID();
    const fencedOperation = randomUUID();
    envs.push(fencedEnv);
    generations.push(fencedGeneration);
    operations.push(fencedOperation);
    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES($1,8453,'private-anvil-fork',$2)`, [fencedEnv, MANIFEST_HASH],
    );
    await pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,
         resource_variant,manifest_sha256,status,expires_at)
       VALUES($1,$2,'sc005-verification-test',$3,$4,'verification_without_receipt',$5,'fenced',clock_timestamp()+interval '1 hour')`,
      [fencedGeneration, fencedEnv, nonce.repeat(2).slice(0, 64), PAYER, MANIFEST_HASH],
    );
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,
         request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'sc005-verification-test',$4,$5,'purchase','awaiting_payment',true)`,
      [fencedOperation, fencedEnv, fencedGeneration, fencedOperation.replaceAll('-', '').repeat(2), REQUEST_HASH],
    );
    await pool.query(
      `UPDATE bef_operation SET selected_offer_id=$2,selected_amount_units=$3,
              offer_selected_at=clock_timestamp(),offer_selection_eligible=false WHERE operation_id=$1`,
      [fencedOperation, OFFER.id, OFFER.amount],
    );
    assert.equal(await recordPrivateVerificationStarted(pool, {
      envId: fencedEnv, generationId: fencedGeneration, operationId: fencedOperation, requestSha256: REQUEST_HASH,
    }, OFFER), false);

    const untouched = await pool.query<{ verification_started_at: Date | null }>(
      `SELECT verification_started_at FROM bef_operation WHERE operation_id=ANY($1::uuid[])`,
      [operations.slice(1)],
    );
    assert.equal(untouched.rows.every((row) => row.verification_started_at === null), true);
  } finally {
    await pool.query('DELETE FROM bef_operation WHERE operation_id=ANY($1::uuid[])', [operations]).catch(() => undefined);
    await pool.query('DELETE FROM bef_generation WHERE generation_id=ANY($1::uuid[])', [generations]).catch(() => undefined);
    await pool.query('DELETE FROM bef_environment WHERE env_id=ANY($1::text[])', [envs]).catch(() => undefined);
    await pool.end();
  }
});
