import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyCombinedRestoreRetryProof } from './beta-backup-restore.mjs';

const hash = (character) => character.repeat(64);
const operationBindings = { bonusGrantOperationsSha256: hash('a'), bonusGrantOperationCount: 0,
  runOperationReceiptsSha256: hash('b'), runOperationReceiptCount: 0,
  runGenerationReceiptsSha256: hash('c'), runGenerationReceiptCount: 0,
  reportOperationReceiptsSha256: hash('d'), reportOperationReceiptCount: 0 };
function snapshot(overrides = {}) {
  return { observerIdentity: { databaseRole: 'oid_observer', databaseName: 'oid_restore_10000000000040008000000000000001', transactionReadOnly: 'on' },
    databaseTotalsSha256: hash('e'), financialStateSha256: hash('f'), benchmarkStateSha256: hash('1'), reportStateSha256: hash('2'),
    reportRateLimitStateSha256: hash('3'), controlOperationalStateSha256: hash('4'),
    operationBindings, imageFiles: [], reportDeletionReceipts: [], reportCount: 0, uploadCount: 0, ...overrides };
}
const originalIds = { completedRunIds: [], queuedInterruptedUnknownRunIds: [], operationIds: [], bonusGrantOperationIds: [], reportOperationIds: [] };
const proof = { status: 'verified', receiptBindings: operationBindings, completedRunIds: [], queuedInterruptedUnknownRunIds: [],
  noNewGrantOrLedgerEffects: true, noNewRunTaskOrActionEffects: true, reportOperationDisposition: 'same_receipts_replayed' };

test('restored UI operational counters may change while business fingerprints remain bound to pre-serve restore', () => {
  const restoredBaseline = snapshot();
  const before = snapshot({ databaseTotalsSha256: hash('5'), controlOperationalStateSha256: hash('6'),
    reportRateLimitStateSha256: hash('7') });
  const after = snapshot({ databaseTotalsSha256: hash('8'), controlOperationalStateSha256: hash('9'),
    reportRateLimitStateSha256: hash('a') });
  const result = verifyCombinedRestoreRetryProof({ restoredBaseline, before, after, retryProof: proof,
    operationBindings, originalIds, retentionExpired: false });
  assert.equal(result.status, 'verified');
  assert.equal(result.controlOperationalState.changedDuringRetryWindow, true);
  assert.equal(result.reportRateLimitState.changedDuringRetryWindow, true);
});

test('restored retry rejects changed report business state even when total database hashes are otherwise arbitrary', () => {
  const restoredBaseline = snapshot();
  const before = snapshot({ databaseTotalsSha256: hash('5') });
  const after = snapshot({ databaseTotalsSha256: hash('8'), reportStateSha256: hash('9') });
  assert.throws(() => verifyCombinedRestoreRetryProof({ restoredBaseline, before, after, retryProof: proof,
    operationBindings, originalIds, retentionExpired: false }), /retry_state_changed/);
});
