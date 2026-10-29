import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { cleanupUnservedRestoreArtifacts, removeOwnedUnsealedRestoreRoot, validateRestoreReceiptPair,
  restoreOfficialEvidenceFiles, verifyCombinedRestoreRetryProof } from './beta-backup-restore.mjs';

const hash = (character) => character.repeat(64);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
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

async function officialFixture(parent, { files, sourceFiles } = {}) {
  const payloadRoot = join(parent, 'payload');
  const restoreDatabaseName = 'oid_restore_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
  const restoreRoot = join(parent, restoreDatabaseName);
  const defaultEvidenceBytes = Buffer.from('bytes-not-copied-into-receipt');
  const rows = files ?? [{ path: 'evidence/official/artifacts/run/action.json', role: 'action_receipt_evidence',
    bytes: defaultEvidenceBytes.length, sha256: sha256(defaultEvidenceBytes) }];
  const sources = sourceFiles ?? [{ path: rows[0].path, bytes: defaultEvidenceBytes }];
  await mkdir(join(payloadRoot, 'evidence'), { recursive: true, mode: 0o700 });
  await mkdir(restoreRoot, { recursive: false, mode: 0o700 });
  await mkdir(join(restoreRoot, 'operator'), { recursive: false, mode: 0o700 });
  for (const source of sources) {
    const path = join(payloadRoot, ...source.path.split('/'));
    await mkdir(join(path, '..'), { recursive: true, mode: 0o700 });
    if (source.symlinkTarget) await symlink(source.symlinkTarget, path, 'file');
    else await writeFile(path, source.bytes, { mode: 0o600 });
  }
  const runIds = ['synthetic-run-id'];
  const sourceBuildSha256 = hash('9');
  const official = { schemaVersion: 'beta-official-evidence-source/v1', sourceProfile: 'local-test',
    runIds, sourceBuildSha256, files: rows };
  const manifestBytes = Buffer.from(JSON.stringify(official) + '\n', 'utf8');
  const manifestPath = join(payloadRoot, 'evidence', 'official-evidence-manifest.json');
  await writeFile(manifestPath, manifestBytes, { mode: 0o600 });
  const payloadManifest = { files: [
    { path: 'evidence/official-evidence-manifest.json', kind: 'evidence', bytes: manifestBytes.length, sha256: sha256(manifestBytes) },
    ...rows.map((row) => ({ path: row.path, kind: 'evidence', bytes: row.bytes, sha256: row.sha256 })),
  ] };
  return { payloadRoot, restoreRoot, restoreDatabaseName, sourceBuildSha256, manifestSha256: sha256(manifestBytes),
    expectedSource: { profile: official.sourceProfile, runIdCount: runIds.length, runIdsSha256: sha256(Buffer.from(JSON.stringify(runIds))) },
    payloadManifest,
    input: { payloadRoot, payloadManifest, restoreRoot, restoreDatabaseName,
      checkpointId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', sourceBuildSha256,
      expectedManifestSha256: sha256(manifestBytes),
      expectedSource: { profile: official.sourceProfile, runIdCount: runIds.length,
        runIdsSha256: sha256(Buffer.from(JSON.stringify(runIds))) } } };
}

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

test('expired restore binds financial/run receipts to source and purged report receipts to the immutable cleanup baseline', () => {
  const sourceBindings = { ...operationBindings, reportOperationReceiptsSha256: hash('8'), reportOperationReceiptCount: 7 };
  const expired = snapshot({ reportDeletionReceipts: [{ reportId: 'expired-report', status: 'complete' }] });
  const expiredProof = { ...proof, receiptBindings: sourceBindings, reportOperationDisposition: 'expired_content_not_replayed' };
  const input = { restoredBaseline: expired, before: expired, after: expired,
    retryProof: expiredProof, operationBindings: sourceBindings, originalIds, retentionExpired: true };
  assert.equal(verifyCombinedRestoreRetryProof(input).status, 'verified');
  assert.throws(() => verifyCombinedRestoreRetryProof({ ...input, after: snapshot({ ...expired,
    operationBindings: { ...operationBindings, runOperationReceiptsSha256: hash('9') } }) }), /retry_operation_bindings_changed/);
  assert.throws(() => verifyCombinedRestoreRetryProof({ ...input, after: snapshot({ ...expired,
    operationBindings: { ...operationBindings, reportOperationReceiptsSha256: hash('9') } }) }), /retry_operation_bindings_changed/);
  assert.throws(() => verifyCombinedRestoreRetryProof({ ...input, restoredBaseline: snapshot(), before: snapshot(), after: snapshot() }),
    /expired_support_purge_receipts_missing/);
  assert.throws(() => verifyCombinedRestoreRetryProof({ ...input, retentionExpired: false }), /retry_operation_bindings_changed/);
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

test('official evidence restore copies every manifest file and writes a bound operator receipt', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-official-restore-'));
  try {
    const fixture = await officialFixture(parent);
    const result = await restoreOfficialEvidenceFiles(fixture.input);
    await rm(fixture.payloadRoot, { recursive: true, force: false });
    assert.equal(result.officialEvidenceRoot, join(fixture.restoreRoot, 'official-evidence'));
    assert.equal(result.officialEvidenceManifestPath, 'operator/official-evidence-manifest.json');
    assert.equal(result.officialEvidenceManifestSha256, fixture.manifestSha256);
    assert.equal(result.verifiedOfficialEvidenceFiles.length, 1);
    const file = result.verifiedOfficialEvidenceFiles[0];
    assert.deepEqual(file, { path: 'official-evidence/artifacts/run/action.json',
      relativePath: 'artifacts/run/action.json', role: 'action_receipt_evidence',
      bytes: Buffer.byteLength('bytes-not-copied-into-receipt'), sha256: sha256(Buffer.from('bytes-not-copied-into-receipt')) });
    assert.equal(await readFile(join(fixture.restoreRoot, ...file.path.split('/')), 'utf8'), 'bytes-not-copied-into-receipt');
    const manifestClonePath = join(fixture.restoreRoot, ...result.officialEvidenceManifestPath.split('/'));
    assert.equal(sha256(await readFile(manifestClonePath)), fixture.manifestSha256);
    const receiptPath = join(fixture.restoreRoot, ...result.officialEvidenceRestoreReceipt.path.split('/'));
    const receiptBytes = await readFile(receiptPath);
    assert.equal(sha256(receiptBytes), result.officialEvidenceRestoreReceipt.sha256);
    if (process.platform !== 'win32') assert.equal((await lstat(receiptPath)).mode & 0o077, 0);
    const receipt = JSON.parse(receiptBytes.toString('utf8'));
    assert.equal(receipt.schemaVersion, 'beta-restored-official-evidence/v1');
    assert.equal(receipt.status, 'restored_verified');
    assert.equal(receipt.checkpointId, fixture.input.checkpointId);
    assert.equal(receipt.sourceBuildSha256, fixture.sourceBuildSha256);
    assert.equal(receipt.restoreDatabaseName, fixture.restoreDatabaseName);
    assert.equal(receipt.manifestPath, 'operator/official-evidence-manifest.json');
    assert.equal(receipt.sourceManifestPath, 'evidence/official-evidence-manifest.json');
    assert.equal(receipt.manifestSha256, fixture.manifestSha256);
    assert.equal(receipt.fileCount, 1);
    assert.deepEqual(receipt.files, result.verifiedOfficialEvidenceFiles);
    assert.equal(JSON.stringify(receipt).includes('bytes-not-copied-into-receipt'), false);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('official evidence restore rejects a file above the bounded per-file limit before materialization', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-official-restore-size-limit-'));
  try {
    const fixture = await officialFixture(parent, { files: [{ path: 'evidence/official/artifacts/run/action.json',
      role: 'action_receipt_evidence', bytes: 64 * 1024 * 1024 + 1, sha256: hash('a') }], sourceFiles: [] });
    await assert.rejects(restoreOfficialEvidenceFiles(fixture.input),
      /beta_backup_restore_official_evidence_file_metadata_invalid/);
    await assert.rejects(lstat(join(fixture.restoreRoot, 'official-evidence')), { code: 'ENOENT' });
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('official evidence restore rejects traversal and case-colliding manifest paths before copying', async () => {
  for (const files of [
    [{ path: 'evidence/official/../private/secret.json', role: 'action_receipt_evidence', bytes: 1, sha256: hash('a') }],
    [
      { path: 'evidence/official/artifacts/run/action.json', role: 'action_receipt_evidence', bytes: 1, sha256: hash('a') },
      { path: 'evidence/official/ARTIFACTS/run/action.json', role: 'action_receipt_evidence', bytes: 1, sha256: hash('b') },
    ],
  ]) {
    const parent = await mkdtemp(join(tmpdir(), 'bpc-official-restore-invalid-path-'));
    try {
      const fixture = await officialFixture(parent, { files, sourceFiles: [] });
      await assert.rejects(restoreOfficialEvidenceFiles(fixture.input),
        /beta_backup_restore_(unsafe_bundle_path|official_evidence_duplicate_path)/);
      await assert.rejects(lstat(join(fixture.restoreRoot, 'official-evidence')), { code: 'ENOENT' });
    } finally { await rm(parent, { recursive: true, force: true }); }
  }
});

test('official evidence restore rejects symlinked sources and bytes that do not match the sealed manifest', async () => {
  const outsideRoot = await mkdtemp(join(tmpdir(), 'bpc-official-restore-outside-'));
  try {
    const outsideFile = join(outsideRoot, 'outside.json');
    await writeFile(outsideFile, 'outside-private-target', { mode: 0o600 });
    const symlinkParent = await mkdtemp(join(tmpdir(), 'bpc-official-restore-symlink-'));
    try {
      const fixture = await officialFixture(symlinkParent, {
        sourceFiles: [{ path: 'evidence/official/artifacts/run/action.json', symlinkTarget: outsideFile }],
      });
      await assert.rejects(restoreOfficialEvidenceFiles(fixture.input), /beta_backup_restore_path_symlink/);
      assert.equal(await readFile(outsideFile, 'utf8'), 'outside-private-target');
    } finally { await rm(symlinkParent, { recursive: true, force: true }); }
    const mismatchParent = await mkdtemp(join(tmpdir(), 'bpc-official-restore-mismatch-'));
    try {
      const expected = Buffer.from('expected');
      const fixture = await officialFixture(mismatchParent, {
        files: [{ path: 'evidence/official/artifacts/run/action.json', role: 'action_receipt_evidence',
          bytes: expected.length, sha256: sha256(expected) }],
        sourceFiles: [{ path: 'evidence/official/artifacts/run/action.json', bytes: Buffer.from('actual') }],
      });
      await assert.rejects(restoreOfficialEvidenceFiles(fixture.input),
        /beta_backup_restore_official_evidence_source_hash_mismatch/);
    } finally { await rm(mismatchParent, { recursive: true, force: true }); }
  } finally { await rm(outsideRoot, { recursive: true, force: true }); }
});
