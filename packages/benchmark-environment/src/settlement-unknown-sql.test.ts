import assert from 'node:assert/strict';
import test from 'node:test';
import { poolFor } from './db.js';
import {
  RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
  RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL,
} from './settlement-unknown-sql.js';

const migrationTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;

test('PostgreSQL binds nullable settlement hashes and preserves terminal or conflicting rows', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.match(url.pathname, /(?:bef[-_])?migration[-_]?test/i, 'the test URL must target a dedicated migration-test database');

  const pool = poolFor(migrationTestUrl);
  const client = await pool.connect();
  try {
    await client.query(`CREATE TEMP TABLE bef_operation (
      operation_id text PRIMARY KEY,
      env_id text NOT NULL,
      status text NOT NULL,
      receipt_status text NOT NULL,
      transaction_hash text,
      completed_at timestamptz
    )`);
    await client.query(`CREATE TEMP TABLE bef_payment (
      operation_id text PRIMARY KEY,
      transaction_hash text,
      receipt_status text NOT NULL,
      observed_at timestamptz
    )`);

    const operationRows = [
      ['unknown-null-hash', 'settling', 'unknown', null],
      ['unknown-original-hash', 'settling', 'unknown', '0x' + 'a'.repeat(64)],
      ['unknown-conflicting-hash', 'settling', 'unknown', '0x' + 'b'.repeat(64)],
      ['terminal-success', 'delivered', 'success', '0x' + 'a'.repeat(64)],
    ] as const;
    for (const [operationId, status, receiptStatus, transactionHash] of operationRows) {
      await client.query(
        'INSERT INTO bef_operation(operation_id,env_id,status,receipt_status,transaction_hash,completed_at) VALUES($1,$2,$3,$4,$5,clock_timestamp())',
        [operationId, 'migration-test', status, receiptStatus, transactionHash],
      );
    }

    const nullHash = await client.query(RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
      ['unknown-null-hash', 'migration-test', null, 'settlement_unknown']);
    const preserveOriginal = await client.query(RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
      ['unknown-original-hash', 'migration-test', null, 'settlement_unknown']);
    const rejectConflict = await client.query(RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
      ['unknown-conflicting-hash', 'migration-test', '0x' + 'c'.repeat(64), 'settlement_unknown']);
    const preserveTerminal = await client.query(RECORD_UNKNOWN_SETTLEMENT_OPERATION_SQL,
      ['terminal-success', 'migration-test', null, 'settlement_unknown']);
    assert.equal(nullHash.rowCount, 1);
    assert.equal(preserveOriginal.rowCount, 1);
    assert.equal(rejectConflict.rowCount, 0);
    assert.equal(preserveTerminal.rowCount, 0);

    const operationState = await client.query<{ operation_id: string; status: string; receipt_status: string; transaction_hash: string | null }>(
      'SELECT operation_id,status,receipt_status,transaction_hash FROM bef_operation ORDER BY operation_id',
    );
    assert.deepEqual(operationState.rows, [
      { operation_id: 'terminal-success', status: 'delivered', receipt_status: 'success', transaction_hash: '0x' + 'a'.repeat(64) },
      { operation_id: 'unknown-conflicting-hash', status: 'settling', receipt_status: 'unknown', transaction_hash: '0x' + 'b'.repeat(64) },
      { operation_id: 'unknown-null-hash', status: 'settlement_unknown', receipt_status: 'unknown', transaction_hash: null },
      { operation_id: 'unknown-original-hash', status: 'settlement_unknown', receipt_status: 'unknown', transaction_hash: '0x' + 'a'.repeat(64) },
    ]);

    const paymentRows = [
      ['payment-null-hash', 'unknown', null],
      ['payment-original-hash', 'unknown', '0x' + 'a'.repeat(64)],
      ['payment-conflicting-hash', 'unknown', '0x' + 'b'.repeat(64)],
      ['payment-terminal-success', 'success', '0x' + 'a'.repeat(64)],
    ] as const;
    for (const [operationId, receiptStatus, transactionHash] of paymentRows) {
      await client.query(
        'INSERT INTO bef_payment(operation_id,receipt_status,transaction_hash) VALUES($1,$2,$3)',
        [operationId, receiptStatus, transactionHash],
      );
    }

    const paymentNullHash = await client.query(RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL, ['payment-null-hash', null]);
    const paymentPreserveOriginal = await client.query(RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL, ['payment-original-hash', null]);
    const paymentRejectConflict = await client.query(RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL, ['payment-conflicting-hash', '0x' + 'c'.repeat(64)]);
    const paymentPreserveTerminal = await client.query(RECORD_UNKNOWN_SETTLEMENT_PAYMENT_SQL, ['payment-terminal-success', null]);
    assert.equal(paymentNullHash.rowCount, 1);
    assert.equal(paymentPreserveOriginal.rowCount, 1);
    assert.equal(paymentRejectConflict.rowCount, 0);
    assert.equal(paymentPreserveTerminal.rowCount, 0);

    const paymentState = await client.query<{ operation_id: string; receipt_status: string; transaction_hash: string | null }>(
      'SELECT operation_id,receipt_status,transaction_hash FROM bef_payment ORDER BY operation_id',
    );
    assert.deepEqual(paymentState.rows, [
      { operation_id: 'payment-conflicting-hash', receipt_status: 'unknown', transaction_hash: '0x' + 'b'.repeat(64) },
      { operation_id: 'payment-null-hash', receipt_status: 'unknown', transaction_hash: null },
      { operation_id: 'payment-original-hash', receipt_status: 'unknown', transaction_hash: '0x' + 'a'.repeat(64) },
      { operation_id: 'payment-terminal-success', receipt_status: 'success', transaction_hash: '0x' + 'a'.repeat(64) },
    ]);
  } finally {
    client.release();
    await pool.end();
  }
});
