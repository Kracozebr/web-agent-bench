import assert from 'node:assert/strict';
import test from 'node:test';
import { validateAcceptanceDatabaseBindings } from './bef-task-executor-bridge-cases.mjs';

const databaseName = `oid_acceptance_${'a'.repeat(32)}`;
const ownerUrl = `postgres://oid_owner:owner-secret@postgres:5432/${databaseName}`;
const observerUrl = `postgres://oid_observer:observer-secret@postgres:5432/${databaseName}`;

test('requires owner and read-only observer to target the same isolated acceptance database', () => {
  assert.equal(validateAcceptanceDatabaseBindings({ databaseUrl: ownerUrl, observerDatabaseUrl: observerUrl }), databaseName);
  assert.throws(() => validateAcceptanceDatabaseBindings({
    databaseUrl: ownerUrl,
    observerDatabaseUrl: `postgres://oid_observer:observer-secret@postgres:5432/oid_acceptance_${'b'.repeat(32)}`,
  }), { message: 'owner_acceptance_database_identity_invalid' });
});

test('rejects product, external, mismatched-role, and query-overridden databases before fixture setup', () => {
  for (const invalidOwnerUrl of [
    'postgres://oid_owner:secret@postgres:5432/owner_identity',
    `postgres://oid_owner:secret@external.invalid:5432/${databaseName}`,
    `postgres://oid_observer:secret@postgres:5432/${databaseName}`,
    `postgres://oid_owner:secret@postgres:5432/${databaseName}?options=-c%20default_transaction_read_only=off`,
  ]) {
    assert.throws(() => validateAcceptanceDatabaseBindings({
      databaseUrl: invalidOwnerUrl, observerDatabaseUrl: observerUrl,
    }), { message: 'owner_acceptance_database_identity_invalid' });
  }
});
