import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';
import {
  applyMigration,
  ensureSchema,
  migrationBody,
  poolFor,
  readMigrationFiles,
  verifySchema,
  type MigrationFile,
} from './db.js';

test('the checked-in SQL migrations use the exact transactional file wrapper', async () => {
  const migrations = await readMigrationFiles();
  assert.deepEqual(migrations.map((migration) => migration.id), ['001', '002', '003', '004', '005', '006', '007', '008', '009', '010']);
  const offerMigration = migrations.find((migration) => migration.id === '005');
  assert.ok(offerMigration);
  assert.match(offerMigration.sql, /selected_offer_id = 'canonical'.*selected_amount_units = 100000/s);
  assert.match(offerMigration.sql, /selected_offer_id = 'task-goal-exceeded'.*selected_amount_units = 3000000/s);
  assert.match(offerMigration.sql, /verification_started_at >= offer_selected_at/);
  assert.match(offerMigration.sql, /bef_operation_selected_offer_pair_ck[\s\S]*\) IS TRUE/);
  assert.match(offerMigration.sql, /bef_operation_verification_after_offer_ck[\s\S]*\) IS TRUE/);
  assert.match(offerMigration.sql, /bef_operation_offer_selection_eligibility_ck[\s\S]*\) IS TRUE/);
  assert.match(offerMigration.sql, /offer_selection_eligible boolean NOT NULL DEFAULT false/);
  assert.match(offerMigration.sql, /bef_preserve_selected_offer_choice/);
  const catalogMigration = migrations.find((migration) => migration.id === '007');
  assert.ok(catalogMigration);
  assert.match(catalogMigration.sql, /selected_resource_id text/);
  assert.match(catalogMigration.sql, /selected_resource_sha256 char\(64\)/);
  assert.match(catalogMigration.sql, /selected_amount_units BETWEEN 1 AND 999999999999/);
  assert.match(catalogMigration.sql, /NEW\.selected_resource_id IS NULL/);
  assert.match(catalogMigration.sql, /selected_resource_sha256/);
  const reconciliationMigration = migrations.find((migration) => migration.id === '008');
  assert.ok(reconciliationMigration);
  assert.match(reconciliationMigration.sql, /'observer_reconciliation'/);
  assert.match(reconciliationMigration.sql, /'receipt_finalized'/);
  const preparationMigration = migrations.find((migration) => migration.id === '009');
  assert.ok(preparationMigration);
  assert.match(preparationMigration.sql, /CREATE TABLE bef_preparation/);
  assert.match(preparationMigration.sql, /preparation_id uuid PRIMARY KEY/);
  assert.match(preparationMigration.sql, /public_pins_sha256 char\(64\)/);
  assert.match(preparationMigration.sql, /status IN \('preparing', 'ready', 'unknown', 'fenced'\)/);
  assert.match(preparationMigration.sql, /fixture_transaction_hash text/);
  assert.match(preparationMigration.sql, /preparation status cannot move backwards/);
  assert.match(preparationMigration.sql, /preparation identities are append-only/);
  for (const migration of migrations) {
    assert.equal(migration.bytes.toString('utf8'), migration.sql);
    assert.equal(createHash('sha256').update(migration.bytes).digest('hex'), migration.sha256);
    assert.match(migration.sql, /^\s*BEGIN;\s*/i);
    assert.match(migration.sql, /\s*COMMIT;\s*$/i);
    assert.equal(migrationBody(migration.sql), migration.sql.replace(/^\s*BEGIN;\s*/i, '').replace(/\s*COMMIT;\s*$/i, ''));
  }
  assert.throws(() => migrationBody('-- leading text is not a wrapper\nBEGIN; SELECT 1; COMMIT;'));
  assert.throws(() => migrationBody('SELECT 1;'));
});

const migrationTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;

test('PostgreSQL migration reruns, checksums, atomic failure, and generation manifest fencing', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase()), 'the migration-test database must be loopback-only');
  const databaseName = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  assert.match(databaseName, /^bef_migration_test_[a-z0-9_]+$/i, 'the test URL must target a dedicated bef_migration_test database');

  const pool = poolFor(migrationTestUrl);
  const nonce = randomUUID().replaceAll('-', '');
  const scratchTable = `bef_migration_probe_${nonce}`;
  const failedTable = `bef_migration_rollback_${nonce}`;
  const envPrefix = `bef-mig-${nonce.slice(0, 20)}`;
  const legacyEnv = `${envPrefix}-legacy`;
  const currentEnv = `${envPrefix}-current`;
  const legacyGeneration = randomUUID();
  const currentGeneration = randomUUID();
  const testOperationIds: string[] = [];
  const manifestHash = 'a'.repeat(64);
  const testMigration = (id: string, filename: string, sql: string): MigrationFile => {
    const bytes = Buffer.from(sql, 'utf8');
    return { id, filename, bytes, sql, sha256: createHash('sha256').update(bytes).digest('hex') };
  };

  try {
    await ensureSchema(pool);
    await verifySchema(pool);

    const good = testMigration('999', '999_test_probe.sql', `BEGIN; CREATE TABLE ${scratchTable}(value integer); COMMIT;`);
    await applyMigration(pool, good);
    const recorded = await pool.query<{ filename: string; sha256: string }>(
      'SELECT filename,sha256 FROM bef_schema_migration WHERE migration_id=$1', ['999'],
    );
    assert.equal(recorded.rows[0]?.filename, good.filename);
    assert.equal(recorded.rows[0]?.sha256.trim(), good.sha256);

    const altered = testMigration('999', '999_test_probe.sql', 'BEGIN; SELECT 1; COMMIT;');
    await assert.rejects(() => applyMigration(pool, altered), /migration checksum mismatch/);

    const failed = testMigration('998', '998_test_rollback.sql', `BEGIN; CREATE TABLE ${failedTable}(value integer); SELECT 1/0; COMMIT;`);
    await assert.rejects(() => applyMigration(pool, failed));
    const rolledBack = await pool.query<{ exists: boolean }>(
      'SELECT to_regclass($1) IS NOT NULL AS exists', [`public.${failedTable}`],
    );
    const failedLedger = await pool.query('SELECT 1 FROM bef_schema_migration WHERE migration_id=$1', ['998']);
    assert.equal(rolledBack.rows[0]?.exists, false);
    assert.equal(failedLedger.rowCount, 0);

    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES ($1,8453,'private-anvil-fork',$3),($2,8453,'private-anvil-fork',$3)`,
      [legacyEnv, currentEnv, manifestHash],
    );
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('ALTER TABLE bef_generation DISABLE TRIGGER bef_generation_manifest_identity_immutable');
      await client.query(
        `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,status,expires_at)
         VALUES($1,$2,'legacy',$3,'0x1111111111111111111111111111111111111111','canonical','active',clock_timestamp()+interval '1 hour')`,
        [legacyGeneration, legacyEnv, 'b'.repeat(64)],
      );
      await client.query('ALTER TABLE bef_generation ENABLE TRIGGER bef_generation_manifest_identity_immutable');
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }

    await pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,manifest_sha256,status,expires_at)
       VALUES($1,$2,'current',$3,'0x2222222222222222222222222222222222222222','canonical',$4,'active',clock_timestamp()+interval '1 hour')`,
      [currentGeneration, currentEnv, 'c'.repeat(64), manifestHash],
    );
    await assert.rejects(() => pool.query(
      'UPDATE bef_generation SET manifest_sha256=$3 WHERE env_id=$1 AND generation_id=$2',
      [currentEnv, currentGeneration, 'd'.repeat(64)],
    ), /manifest identity is immutable/);
    await assert.rejects(() => pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,status,expires_at)
       VALUES($1,$2,'missing-pin',$3,'0x3333333333333333333333333333333333333333','canonical','active',clock_timestamp()+interval '1 hour')`,
      [randomUUID(), currentEnv, 'e'.repeat(64)],
    ), /requires a pinned manifest identity/);

    await assert.rejects(() => pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,operation_kind,status,selected_offer_id,offer_selected_at)
       VALUES($1,$2,$3,'partial',$4,$5,'purchase','awaiting_payment','canonical',clock_timestamp())`,
      [randomUUID(), currentEnv, currentGeneration, '1'.repeat(64), '2'.repeat(64)],
    ), /bef_operation_selected_offer_pair_ck/);

    const canonicalOperationId = randomUUID();
    testOperationIds.push(canonicalOperationId);
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'canonical-choice',$4,$5,'purchase','awaiting_payment',true)`,
      [canonicalOperationId, currentEnv, currentGeneration, '3'.repeat(64), '4'.repeat(64)],
    );
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET status='verifying',verification_started_at=clock_timestamp() WHERE operation_id=$1`,
      [canonicalOperationId],
    ), /verification must follow an immutable selected offer/);
    await pool.query(
      `UPDATE bef_operation SET selected_offer_id='canonical',selected_amount_units=100000,
              selected_resource_id='bef-resource-v1',selected_resource_sha256=$2,
              offer_selected_at=clock_timestamp(),offer_selection_eligible=false WHERE operation_id=$1`,
      [canonicalOperationId, manifestHash],
    );
    await pool.query(
      `UPDATE bef_operation SET status='verifying',verification_started_at=clock_timestamp() WHERE operation_id=$1`,
      [canonicalOperationId],
    );

    const selectedOperationId = randomUUID();
    testOperationIds.push(selectedOperationId);
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'selected',$4,$5,'purchase','awaiting_payment',true)`,
      [selectedOperationId, currentEnv, currentGeneration, '5'.repeat(64), '6'.repeat(64)],
    );
    await pool.query(
      `UPDATE bef_operation SET selected_offer_id='task-goal-exceeded',selected_amount_units=3000000,
              selected_resource_id='bef-resource-v1',selected_resource_sha256=$2,
              offer_selected_at=clock_timestamp(),offer_selection_eligible=false WHERE operation_id=$1`,
      [selectedOperationId, manifestHash],
    );
    await pool.query(
      `UPDATE bef_operation SET status='verifying',verification_started_at=clock_timestamp() WHERE operation_id=$1`,
      [selectedOperationId],
    );
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_offer_id='canonical' WHERE operation_id=$1`,
      [selectedOperationId],
    ), /selected offer choice is immutable/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_amount_units=2000000 WHERE operation_id=$1`,
      [selectedOperationId],
    ), /selected offer choice is immutable/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET offer_selected_at=offer_selected_at+interval '1 second' WHERE operation_id=$1`,
      [selectedOperationId],
    ), /selected offer choice is immutable/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET verification_started_at=verification_started_at+interval '1 second' WHERE operation_id=$1`,
      [selectedOperationId],
    ), /verification must follow an immutable selected offer/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET verification_started_at=offer_selected_at-interval '1 second' WHERE operation_id=$1`,
      [selectedOperationId],
    ), /verification must follow an immutable selected offer/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_offer_id=NULL WHERE operation_id=$1`,
      [selectedOperationId],
    ), /selected offer choice is immutable/);

    const resourceChoiceOperationId = randomUUID();
    testOperationIds.push(resourceChoiceOperationId);
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,operation_kind,status,offer_selection_eligible)
       VALUES($1,$2,$3,'resource-choice',$4,$5,'purchase','awaiting_payment',true)`,
      [resourceChoiceOperationId, currentEnv, currentGeneration, 'd'.repeat(64), 'e'.repeat(64)],
    );
    await pool.query(
      `UPDATE bef_operation SET selected_offer_id='market-brief-standard',selected_amount_units=125000,
              selected_resource_id='bef-market-state-brief-v1',selected_resource_sha256=$2,
              offer_selected_at=clock_timestamp(),offer_selection_eligible=false WHERE operation_id=$1`,
      [resourceChoiceOperationId, 'b'.repeat(64)],
    );
    await pool.query(
      `UPDATE bef_operation SET status='verifying',verification_started_at=clock_timestamp() WHERE operation_id=$1`,
      [resourceChoiceOperationId],
    );
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_resource_id='bef-resource-v1' WHERE operation_id=$1`,
      [resourceChoiceOperationId],
    ), /selected offer choice is immutable/);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_resource_sha256=$2 WHERE operation_id=$1`,
      [resourceChoiceOperationId, 'c'.repeat(64)],
    ), /selected offer choice is immutable/);

    const legacyOperationId = randomUUID();
    testOperationIds.push(legacyOperationId);
    await pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,operation_kind,status)
       VALUES($1,$2,$3,'legacy-terminal',$4,$5,'purchase','delivered')`,
      [legacyOperationId, currentEnv, currentGeneration, 'b'.repeat(64), 'c'.repeat(64)],
    );
    const untouchedLegacy = await pool.query<{ selected_offer_id: string | null; selected_amount_units: string | null; offer_selected_at: Date | null }>(
      `SELECT selected_offer_id,selected_amount_units::text,offer_selected_at FROM bef_operation WHERE operation_id=$1`,
      [legacyOperationId],
    );
    assert.equal(untouchedLegacy.rows[0]?.selected_offer_id, null);
    assert.equal(untouchedLegacy.rows[0]?.selected_amount_units, null);
    assert.equal(untouchedLegacy.rows[0]?.offer_selected_at, null);
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET selected_offer_id='canonical',selected_amount_units=100000,offer_selected_at=clock_timestamp()
        WHERE operation_id=$1`,
      [legacyOperationId],
    ), /selected offer choice is immutable or not eligible/);

    const nullOfferPairId = randomUUID();
    testOperationIds.push(nullOfferPairId);
    await assert.rejects(() => pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,
         operation_kind,status,selected_offer_id,selected_amount_units,offer_selected_at,offer_selection_eligible)
       VALUES($1,$2,$3,'null-offer-pair',$4,$5,'purchase','awaiting_payment','canonical',NULL,NULL,false)`,
      [nullOfferPairId, currentEnv, currentGeneration, '7'.repeat(64), '8'.repeat(64)],
    ), /bef_operation_selected_offer_pair_ck/);

    const nullVerificationId = randomUUID();
    testOperationIds.push(nullVerificationId);
    await assert.rejects(() => pool.query(
      `INSERT INTO bef_operation(operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,request_sha256,
         operation_kind,status,verification_started_at)
       VALUES($1,$2,$3,'null-verification-choice',$4,$5,'purchase','verifying',clock_timestamp())`,
      [nullVerificationId, currentEnv, currentGeneration, '9'.repeat(64), 'a'.repeat(64)],
    ), /bef_operation_verification_after_offer_ck/);

    await pool.query(`UPDATE bef_generation SET status='fenced' WHERE env_id=$1 AND generation_id=$2`, [legacyEnv, legacyGeneration]);
    await assert.rejects(() => pool.query(
      'UPDATE bef_generation SET manifest_sha256=$3 WHERE env_id=$1 AND generation_id=$2',
      [legacyEnv, legacyGeneration, manifestHash],
    ), /manifest identity is immutable/);
  } finally {
    if (testOperationIds.length) await pool.query('DELETE FROM bef_operation WHERE operation_id = ANY($1::uuid[])', [testOperationIds]).catch(() => undefined);
    await pool.query('DELETE FROM bef_generation WHERE env_id = ANY($1::text[])', [[legacyEnv, currentEnv]]).catch(() => undefined);
    await pool.query('DELETE FROM bef_environment WHERE env_id = ANY($1::text[])', [[legacyEnv, currentEnv]]).catch(() => undefined);
    await pool.query('DELETE FROM bef_schema_migration WHERE migration_id = ANY($1::text[])', [['998', '999']]).catch(() => undefined);
    await pool.query(`DROP TABLE IF EXISTS ${scratchTable}`).catch(() => undefined);
    await pool.query(`DROP TABLE IF EXISTS ${failedTable}`).catch(() => undefined);
    await pool.end();
  }

  const verificationPool = poolFor(migrationTestUrl);
  try { await verifySchema(verificationPool); } finally { await verificationPool.end(); }
});
