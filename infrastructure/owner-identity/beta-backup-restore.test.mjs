import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { cleanupUnservedRestoreArtifacts, removeOwnedUnsealedRestoreRoot, validateRestoreReceiptPair,
  verifyCombinedRestoreRetryProof } from './beta-backup-restore.mjs';

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

test('restore receipt pair binds the host creation and pg_restore jobs to the exact fresh database and dump', () => {
  const restoreDatabaseName = 'oid_restore_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const checkpointId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const databaseDumpSha256 = hash('5');
  const creationReceipt = { status: 'complete', kind: 'create_restore_database', jobId: 'a'.repeat(32),
    databaseName: restoreDatabaseName, checkpointId, creationJobId: 'a'.repeat(32), createdFresh: true };
  const restoreReceipt = { status: 'restored', kind: 'pg_restore', jobId: 'b'.repeat(32),
    databaseName: restoreDatabaseName, checkpointId, creationJobId: 'a'.repeat(32), dumpSha256: databaseDumpSha256,
    restored: true };
  const result = validateRestoreReceiptPair({ restoreDatabaseName, checkpointId, databaseDumpSha256,
    creationReceipt, restoreReceipt });
  assert.equal(result.creationReceipt.jobId, creationReceipt.creationJobId);
  assert.equal(result.restoreReceipt.creationJobId, creationReceipt.jobId);
  assert.equal(result.restoreReceipt.dumpSha256, databaseDumpSha256);
  for (const [receipt, key, value] of [
    [creationReceipt, 'jobId', 'not-a-host-job-id'],
    [creationReceipt, 'createdFresh', false],
    [restoreReceipt, 'jobId', creationReceipt.jobId],
    [restoreReceipt, 'creationJobId', 'c'.repeat(32)],
    [restoreReceipt, 'dumpSha256', hash('6')],
    [restoreReceipt, 'restored', false],
  ]) {
    const changed = { ...receipt, [key]: value };
    assert.throws(() => validateRestoreReceiptPair({ restoreDatabaseName, checkpointId, databaseDumpSha256,
      creationReceipt: receipt === creationReceipt ? changed : creationReceipt,
      restoreReceipt: receipt === restoreReceipt ? changed : restoreReceipt }), /restore_receipt_pair_invalid/);
  }
});

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

test('failed unserved restore removes its unique plaintext root and records only safe failure identity', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-restore-failure-'));
  const databaseName = 'oid_restore_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const restoreRoot = join(parent, databaseName);
  const privateImage = join(restoreRoot, 'private-data', 'reports', 'images', 'image.webp');
  try {
    await mkdir(join(restoreRoot, 'private-data', 'reports', 'images'), { recursive: true, mode: 0o700 });
    await writeFile(privateImage, 'private-image-bytes', { mode: 0o600 });
    const result = await cleanupUnservedRestoreArtifacts({ restoreParent: parent, restoreRoot, restoreRootCreated: true,
      checkpointId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', restoreDatabaseName: databaseName,
      reasonCode: 'restored_database_or_images_mismatch', databaseDisposition: 'preserved_unserved_for_inspection' });

    assert.equal(result.restoreRootDisposition, 'removed');
    assert.equal(result.databaseDisposition, 'preserved_unserved_for_inspection');
    await assert.rejects(lstat(restoreRoot), { code: 'ENOENT' });
    const receipt = JSON.parse(await readFile(result.failureReceipt.path, 'utf8'));
    assert.equal(receipt.status, 'failed_unserved');
    assert.equal(receipt.restoreDatabaseName, databaseName);
    assert.equal(receipt.reasonCode, 'restored_database_or_images_mismatch');
    assert.equal(receipt.databaseDisposition, 'preserved_unserved_for_inspection');
    assert.equal(JSON.stringify(receipt).includes('private-image-bytes'), false);
    assert.equal(createHash('sha256').update(await readFile(result.failureReceipt.path)).digest('hex'), result.failureReceipt.sha256);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('failed restore cleanup refuses an unexpected symlink root and retains a safe failure receipt', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-restore-failure-symlink-'));
  const databaseName = 'oid_restore_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const restoreRoot = join(parent, databaseName);
  const outside = join(parent, 'outside-owned-by-test');
  try {
    await mkdir(outside, { recursive: false, mode: 0o700 });
    await writeFile(join(outside, 'marker.txt'), 'preserve-outside-root', { mode: 0o600 });
    await symlink(outside, restoreRoot, 'dir');
    const result = await cleanupUnservedRestoreArtifacts({ restoreParent: parent, restoreRoot, restoreRootCreated: true,
      checkpointId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', restoreDatabaseName: databaseName,
      reasonCode: 'restore_failed' });

    assert.equal(result.restoreRootDisposition, 'retained_cleanup_failed');
    assert.equal(await readFile(join(outside, 'marker.txt'), 'utf8'), 'preserve-outside-root');
    const receipt = JSON.parse(await readFile(result.failureReceipt.path, 'utf8'));
    assert.equal(receipt.restoreRootDisposition, 'retained_cleanup_failed');
    assert.equal((await lstat(restoreRoot)).isSymbolicLink(), true);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('successful unseal cleanup removes only the contained staging directory', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-unsealed-cleanup-'));
  const databaseName = 'oid_restore_cccccccccccccccccccccccccccccccc';
  const restoreRoot = join(parent, databaseName);
  const unsealedRoot = join(restoreRoot, 'unsealed');
  try {
    await mkdir(join(unsealedRoot, 'evidence'), { recursive: true, mode: 0o700 });
    await writeFile(join(unsealedRoot, 'evidence', 'source-after.json'), 'private-stage', { mode: 0o600 });
    await mkdir(join(restoreRoot, 'operator'), { recursive: false, mode: 0o700 });
    await writeFile(join(restoreRoot, 'operator', 'authoritative-closure.json'), 'closure-state', { mode: 0o600 });
    assert.equal(await removeOwnedUnsealedRestoreRoot({ restoreParent: parent, restoreRoot, unsealedRoot, restoreDatabaseName: databaseName }), 'removed');
    await assert.rejects(lstat(unsealedRoot), { code: 'ENOENT' });
    assert.equal(await readFile(join(restoreRoot, 'operator', 'authoritative-closure.json'), 'utf8'), 'closure-state');
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('unseal cleanup refuses symlinked staging and leaves its target untouched', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-unsealed-symlink-'));
  const databaseName = 'oid_restore_dddddddddddddddddddddddddddddddd';
  const restoreRoot = join(parent, databaseName);
  const unsealedRoot = join(restoreRoot, 'unsealed');
  const outside = join(parent, 'outside-owned-by-test');
  try {
    await mkdir(restoreRoot, { recursive: false, mode: 0o700 });
    await mkdir(outside, { recursive: false, mode: 0o700 });
    await writeFile(join(outside, 'marker.txt'), 'preserve-outside-root', { mode: 0o600 });
    await symlink(outside, unsealedRoot, 'dir');
    await assert.rejects(removeOwnedUnsealedRestoreRoot({ restoreParent: parent, restoreRoot, unsealedRoot,
      restoreDatabaseName: databaseName }), /beta_backup_restore_unsealed_cleanup_path_invalid/);
    assert.equal(await readFile(join(outside, 'marker.txt'), 'utf8'), 'preserve-outside-root');
    assert.equal((await lstat(unsealedRoot)).isSymbolicLink(), true);
  } finally { await rm(parent, { recursive: true, force: true }); }
});
