import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectBackupFile, validateBackupInventory, verifyBackupFiles, planBackupRotation } from './beta-backup-inventory.mjs';

const hash = 'a'.repeat(64);
function manifest(files, extra = {}) {
  return { schemaVersion: 'beta-backup-inventory/v1', checkpointId: '10000000-0000-4000-8000-000000000001',
    kind: 'daily', failureDomain: 'same_host', sourceBuildSha256: hash,
    capturedAt: '2026-10-28T12:00:00.000Z', betaEndedAt: null,
    reconciliationEvidenceSha256: hash, databaseTotalsSha256: hash,
    files, reportDeletionReceipts: [], ...extra };
}
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'bpc-backup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'images'));
  await writeFile(join(root, 'database.dump'), 'synthetic dump bytes; not a database acceptance fixture');
  await writeFile(join(root, 'images', 'one.webp'), 'synthetic image bytes; integrity test only');
  return { root, database: await inspectBackupFile(root, 'database.dump', 'database'),
    image: await inspectBackupFile(root, 'images/one.webp', 'screenshot') };
}

test('unexpired checkpoint verifies referenced bytes but never authorizes restored writes', async (t) => {
  const { root, database, image } = await fixture(t);
  const result = await verifyBackupFiles(root, manifest([database, image]), { now: '2026-10-29T12:00:00.000Z' });
  assert.equal(result.integrity, 'passed');
  assert.equal(result.checkpointAgeSeconds, 86400);
  assert.equal(result.writesMayBeEnabled, false);
  assert.equal(result.restoreAcceptance, 'not_run');
  await writeFile(join(root, 'images', 'one.webp'), 'corrupted');
  await assert.rejects(verifyBackupFiles(root, manifest([database, image])), /file_integrity/);
});

test('missing screenshot and escaping or symlink paths cannot produce a complete file verification', async (t) => {
  const { root, database, image } = await fixture(t);
  for (const path of ['../outside', '/outside', 'C:/outside', 'images/../database.dump', 'images\\one.webp']) {
    assert.throws(() => validateBackupInventory(manifest([{ ...database, path }])), /invalid_path/);
  }
  assert.throws(() => validateBackupInventory(manifest([database, { ...database, path: 'DATABASE.dump' } ])), /duplicate_path/);
  await rm(join(root, 'images', 'one.webp'));
  await assert.rejects(verifyBackupFiles(root, manifest([database, image])), /ENOENT/);
  await symlink(join(root, 'database.dump'), join(root, 'images', 'linked'));
  await assert.rejects(inspectBackupFile(root, 'images/linked', 'evidence'), /symlink/);
});

test('old pre-closure checkpoint cannot bypass an authoritative 30-day report deadline', async (t) => {
  const { root, database, image } = await fixture(t);
  const options = { now: '2026-11-27T12:00:00.000Z', authoritativeBetaEndedAt: '2026-10-28T12:00:00.000Z' };
  await assert.rejects(verifyBackupFiles(root, manifest([database, image]), options), /restore_requires_report_purge/);
  const sanitized = manifest([database], { kind: 'retention_sanitized', capturedAt: options.now,
    betaEndedAt: options.authoritativeBetaEndedAt, sanitizationEvidenceSha256: hash });
  const result = await verifyBackupFiles(root, sanitized, options);
  assert.equal(result.reportRetentionExpired, true);
  assert.equal(result.writesMayBeEnabled, false);
  assert.throws(() => validateBackupInventory({ ...sanitized, reportDeletionReceipts: [
    { reportId: '20000000-0000-4000-8000-000000000001', status: 'failed' },
  ] }), /expired_content_checkpoint/);
});

test('rotation bounds daily copies and the latest pre-migration checkpoint without deleting files', () => {
  const database = { path: 'database.dump', bytes: 10, sha256: hash, kind: 'database' };
  const rows = Array.from({ length: 10 }, (_, index) => manifest([database], {
    checkpointId: `10000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    capturedAt: `2026-10-${String(index + 10).padStart(2, '0')}T12:00:00.000Z`,
  }));
  rows.push(manifest([database], { kind: 'pre_migration', checkpointId: '30000000-0000-4000-8000-000000000001' }));
  const plan = planBackupRotation(rows);
  assert.equal(plan.keep.length, 8);
  assert.equal(plan.retire.length, 3);
  assert.ok(plan.keep.includes(rows.at(-1).checkpointId));
  const expired = planBackupRotation(rows, { now: '2026-11-27T12:00:00.000Z',
    authoritativeBetaEndedAt: '2026-10-28T12:00:00.000Z' });
  assert.deepEqual(expired.keep, []);
  assert.equal(expired.retire.length, rows.length);
});

test('v2 encrypted inventory verifies a single sealed bundle and recovery-envelope binding', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'bpc-sealed-inventory-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, 'checkpoint.bundle.enc'), Buffer.from('sealed bundle bytes'));
  const artifact = await inspectBackupFile(root, 'checkpoint.bundle.enc', 'sealed_bundle');
  const sealed = manifest([artifact], {
    schemaVersion: 'beta-backup-inventory/v2', checkpointId: '40000000-0000-4000-8000-000000000001',
    payloadManifestSha256: hash, recoveryEnvelopeSha256: hash,
    payloadSummary: { reportCount: 0, uploadCount: 0, screenshotCount: 0, screenshotBytes: 0,
      officialEvidenceFileCount: 1, databaseDumpBytes: 128 },
    checkpointSource: { sourceDatabase: 'owner_identity', boundary: 'admission_frozen_database_quiescent',
      snapshotBoundaryId: randomUUID(), sourceSnapshotAt: '2026-10-28T12:00:00.000Z',
      sourceAfterSnapshotAt: '2026-10-28T12:00:00.001Z',
      officialEvidenceSource: { profile: 'test', runIdCount: 1, runIdsSha256: hash },
      operationBindings: { bonusGrantOperationsSha256: hash, bonusGrantOperationCount: 0,
        runOperationReceiptsSha256: hash, runOperationReceiptCount: 0, runGenerationReceiptsSha256: hash,
        runGenerationReceiptCount: 0, reportOperationReceiptsSha256: hash, reportOperationReceiptCount: 0 } },
    operationBindings: { bonusGrantOperationsSha256: hash, bonusGrantOperationCount: 0,
      runOperationReceiptsSha256: hash, runOperationReceiptCount: 0, runGenerationReceiptsSha256: hash,
      runGenerationReceiptCount: 0, reportOperationReceiptsSha256: hash, reportOperationReceiptCount: 0 },
  });
  const result = await verifyBackupFiles(root, sealed, { now: '2026-10-29T12:00:00.000Z' });
  assert.equal(result.integrity, 'passed');
  assert.equal(result.writesMayBeEnabled, false);
  assert.throws(() => validateBackupInventory({ ...sealed, recoveryEnvelopeSha256: undefined }), /database_count/);
});

test('v2 retention-sanitized checkpoints require zero support content and complete deletion receipts', () => {
  const sealedBundle = { path: 'checkpoint.bundle.enc', bytes: 42, sha256: hash, kind: 'sealed_bundle' };
  const operationBindings = { bonusGrantOperationsSha256: hash, bonusGrantOperationCount: 0,
    runOperationReceiptsSha256: hash, runOperationReceiptCount: 0, runGenerationReceiptsSha256: hash,
    runGenerationReceiptCount: 0, reportOperationReceiptsSha256: hash, reportOperationReceiptCount: 0 };
  const base = manifest([sealedBundle], {
    schemaVersion: 'beta-backup-inventory/v2', checkpointId: '40000000-0000-4000-8000-000000000002',
    kind: 'retention_sanitized', betaEndedAt: '2026-09-01T00:00:00.000Z',
    sanitizationEvidenceSha256: hash, payloadManifestSha256: hash, recoveryEnvelopeSha256: hash,
    payloadSummary: { reportCount: 0, uploadCount: 0, screenshotCount: 0, screenshotBytes: 0,
      officialEvidenceFileCount: 1, databaseDumpBytes: 128 }, operationBindings,
    checkpointSource: { sourceDatabase: 'owner_identity', boundary: 'admission_frozen_database_quiescent', operationBindings },
  });
  assert.equal(validateBackupInventory(base), base);
  assert.throws(() => validateBackupInventory({ ...base, payloadSummary: { ...base.payloadSummary, screenshotCount: 1 } }),
    /expired_content_checkpoint/);
  assert.throws(() => validateBackupInventory({ ...base, reportDeletionReceipts: [
    { reportId: '50000000-0000-4000-8000-000000000001', status: 'pending' },
  ] }), /expired_content_checkpoint/);
});
