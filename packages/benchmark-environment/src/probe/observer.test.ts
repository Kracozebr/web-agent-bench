import assert from 'node:assert/strict';
import test from 'node:test';
import { snapshotObservationIdentity, type SnapshotSelector } from './observer.js';

test('database snapshot identity is recorded even without a generation observation scope', () => {
  const selector: SnapshotSelector = {
    envId: 'bef-test',
    generationId: '11111111-1111-4111-8111-111111111111',
    variantId: 'unsupported_asset_boundary_rejected',
    label: 'sc007-denial-before',
  };
  assert.deepEqual(snapshotObservationIdentity(selector, 'on'), {
    envId: selector.envId,
    generationId: selector.generationId,
    transactionReadOnly: 'on',
  });
});

test('database snapshot identity rejects evidence without an observed read-only transaction', () => {
  const selector: SnapshotSelector = {
    envId: 'bef-test',
    generationId: '11111111-1111-4111-8111-111111111111',
    variantId: 'unsupported_asset_boundary_rejected',
    label: 'sc007-denial-before',
  };
  assert.throws(() => snapshotObservationIdentity(selector, 'off'), /probe_database_snapshot_not_readonly/);
});
