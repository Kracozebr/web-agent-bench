import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KINDS = new Set(['database', 'evidence', 'screenshot', 'sealed_bundle']);
const DAY = 86_400_000;

function fail(reason) { throw new Error(`beta_backup_${reason}`); }
function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) fail('invalid_time');
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) fail('invalid_time');
  return time;
}

function safeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') ||
      isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) fail('invalid_path');
  return value;
}

async function regularFile(root, path) {
  const resolvedRoot = await realpath(root);
  let target = resolvedRoot;
  // AICODE-NOTE: Inventory paths are operator data, not trusted filesystem instructions.
  // Reject symlinks in every component rather than hashing outside the private bundle.
  for (const part of safeRelative(path).split('/')) {
    target = resolve(target, part);
    const info = await lstat(target);
    if (info.isSymbolicLink()) fail('symlink');
  }
  const canonical = await realpath(target);
  const inside = relative(resolvedRoot, canonical);
  if (!inside || inside === '..' || inside.startsWith(`..${sep}`) || isAbsolute(inside)) fail('path_escape');
  if (!(await lstat(canonical)).isFile()) fail('not_regular_file');
  return canonical;
}

export async function inspectBackupFile(root, path, kind) {
  if (!KINDS.has(kind)) fail('invalid_file_kind');
  const file = await regularFile(root, path);
  const handle = await open(file, 'r');
  try {
    const before = await handle.stat();
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await handle.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino) fail('file_changed');
    return { path, kind, bytes: after.size, sha256: hash.digest('hex') };
  } finally { await handle.close(); }
}

export function validateBackupInventory(value) {
  const sealed = value?.schemaVersion === 'beta-backup-inventory/v2';
  if (!value || (!sealed && value.schemaVersion !== 'beta-backup-inventory/v1') ||
      !UUID.test(value.checkpointId ?? '') ||
      !['daily', 'pre_migration', 'retention_sanitized'].includes(value.kind) ||
      value.failureDomain !== 'same_host' || !HASH.test(value.sourceBuildSha256 ?? '') ||
      !Array.isArray(value.files) || !Array.isArray(value.reportDeletionReceipts)) fail('invalid_inventory');
  const capturedAt = timestamp(value.capturedAt);
  if (!HASH.test(value.reconciliationEvidenceSha256 ?? '') || !HASH.test(value.databaseTotalsSha256 ?? '')) fail('missing_reconciliation_binding');
  const paths = new Set();
  let databases = 0;
  let sealedBundles = 0;
  for (const row of value.files) {
    safeRelative(row.path);
    const collisionKey = row.path.toLowerCase();
    if (paths.has(collisionKey)) fail('duplicate_path');
    paths.add(collisionKey);
    if (!KINDS.has(row.kind) || !Number.isSafeInteger(row.bytes) || row.bytes < 0 || !HASH.test(row.sha256 ?? '')) fail('invalid_file');
    if (row.kind === 'database') { databases++; if (row.bytes === 0) fail('empty_database'); }
    if (row.kind === 'sealed_bundle') { sealedBundles++; if (row.bytes === 0 || row.path !== 'checkpoint.bundle.enc') fail('sealed_bundle_invalid'); }
  }
  if (sealed ? (sealedBundles !== 1 || databases !== 0 || value.files.length !== 1 || !value.payloadSummary ||
      !Number.isSafeInteger(value.payloadSummary.reportCount) || value.payloadSummary.reportCount < 0 ||
      !Number.isSafeInteger(value.payloadSummary.uploadCount) || value.payloadSummary.uploadCount < 0 ||
      !Number.isSafeInteger(value.payloadSummary.screenshotCount) || value.payloadSummary.screenshotCount < 0 ||
      !HASH.test(value.payloadManifestSha256 ?? '') || !value.checkpointSource ||
      !HASH.test(value.recoveryEnvelopeSha256 ?? '') ||
      value.checkpointSource.boundary !== 'admission_frozen_database_quiescent' ||
      !HASH.test(value.operationBindings?.bonusGrantOperationsSha256 ?? '') ||
      !HASH.test(value.operationBindings?.runOperationReceiptsSha256 ?? '') ||
      !HASH.test(value.operationBindings?.runGenerationReceiptsSha256 ?? '') ||
      !HASH.test(value.operationBindings?.reportOperationReceiptsSha256 ?? '') ||
      !Number.isSafeInteger(value.operationBindings?.bonusGrantOperationCount) ||
      !Number.isSafeInteger(value.operationBindings?.runOperationReceiptCount) ||
      !Number.isSafeInteger(value.operationBindings?.runGenerationReceiptCount) ||
      !Number.isSafeInteger(value.operationBindings?.reportOperationReceiptCount)) : databases !== 1) fail('database_count');
  const ids = new Set();
  for (const receipt of value.reportDeletionReceipts) {
    if (!receipt || !UUID.test(receipt.reportId ?? '') || ids.has(receipt.reportId) ||
        !['pending', 'failed', 'complete'].includes(receipt.status)) fail('invalid_deletion_receipt');
    ids.add(receipt.reportId);
  }
  if (value.betaEndedAt !== null) {
    const expiry = timestamp(value.betaEndedAt) + 30 * DAY;
    const containsSupportContent = sealed ? value.payloadSummary.reportCount > 0 || value.payloadSummary.uploadCount > 0 ||
      value.payloadSummary.screenshotCount > 0 : value.files.some((file) => file.kind === 'screenshot');
    if (capturedAt >= expiry && (value.kind !== 'retention_sanitized' || containsSupportContent ||
        value.reportDeletionReceipts.some((receipt) => receipt.status !== 'complete') ||
        !HASH.test(value.sanitizationEvidenceSha256 ?? ''))) fail('expired_content_checkpoint');
  }
  return value;
}

/** File bytes only: this never establishes DB consistency, correct totals, retention safety, or safe operation retries. */
export async function verifyBackupIntegrity(root, inventory) {
  validateBackupInventory(inventory);
  for (const row of inventory.files) {
    const observed = await inspectBackupFile(root, row.path, row.kind);
    if (observed.sha256 !== row.sha256 || observed.bytes !== row.bytes) fail('file_integrity');
  }
  return {
    schemaVersion: 'beta-backup-file-integrity/v1', checkpointId: inventory.checkpointId,
    fileCount: inventory.files.length, integrity: 'passed', writesMayBeEnabled: false,
  };
}

/** Integrity plus current retention eligibility; neither result authorizes restored writes. */
export async function verifyBackupFiles(root, inventory, { now = new Date().toISOString(), authoritativeBetaEndedAt } = {}) {
  validateBackupInventory(inventory);
  const current = timestamp(now);
  const source = timestamp(inventory.capturedAt);
  if (current < source) fail('future_checkpoint');
  const closureTimes = [inventory.betaEndedAt, authoritativeBetaEndedAt].filter((value) => value !== null && value !== undefined).map(timestamp);
  const expiry = closureTimes.length ? Math.min(...closureTimes) + 30 * DAY : null;
  // A newer operator closure/tombstone survives restore from an older pre-closure dump.
  // Missing external closure state must be resolved before enabling any restored access.
  const expired = expiry !== null && current >= expiry;
  const containsSupportContent = inventory.schemaVersion === 'beta-backup-inventory/v2'
    ? inventory.payloadSummary.reportCount > 0 || inventory.payloadSummary.uploadCount > 0 || inventory.payloadSummary.screenshotCount > 0
    : inventory.files.some((file) => file.kind === 'screenshot');
  if (expired && (inventory.kind !== 'retention_sanitized' || containsSupportContent ||
      inventory.reportDeletionReceipts.some((receipt) => receipt.status !== 'complete') || !HASH.test(inventory.sanitizationEvidenceSha256 ?? ''))) {
    fail('restore_requires_report_purge');
  }
  const integrity = await verifyBackupIntegrity(root, inventory);
  return {
    schemaVersion: 'beta-backup-file-verification/v1', checkpointId: inventory.checkpointId,
    verifiedAt: now, fileCount: inventory.files.length, checkpointAgeSeconds: (current - source) / 1000,
    reportRetentionExpired: expired, failureDomain: 'same_host', integrity: 'passed',
    restoreAcceptance: 'not_run', writesMayBeEnabled: integrity.writesMayBeEnabled,
  };
}

/** Returns identifiers only. Deletion is a separate operator action after a verified checkpoint. */
export function planBackupRotation(inventories, { now = new Date().toISOString(), authoritativeBetaEndedAt } = {}) {
  for (const inventory of inventories) validateBackupInventory(inventory);
  if (new Set(inventories.map((item) => item.checkpointId)).size !== inventories.length) fail('duplicate_checkpoint');
  const current = timestamp(now);
  const ordered = [...inventories].sort((a, b) => timestamp(b.capturedAt) - timestamp(a.capturedAt) || a.checkpointId.localeCompare(b.checkpointId));
  const eligible = ordered.filter((item) => {
    const closures = [item.betaEndedAt, authoritativeBetaEndedAt].filter((value) => value !== null && value !== undefined).map(timestamp);
    const expired = closures.length > 0 && current >= Math.min(...closures) + 30 * DAY;
    const containsSupportContent = item.schemaVersion === 'beta-backup-inventory/v2'
      ? item.payloadSummary.reportCount > 0 || item.payloadSummary.uploadCount > 0 || item.payloadSummary.screenshotCount > 0
      : item.files.some((file) => file.kind === 'screenshot');
    return !expired || (item.kind === 'retention_sanitized' && !containsSupportContent &&
      item.reportDeletionReceipts.every((receipt) => receipt.status === 'complete') && HASH.test(item.sanitizationEvidenceSha256 ?? ''));
  });
  const keep = new Set(eligible.filter((item) => item.kind === 'daily' || item.kind === 'retention_sanitized').slice(0, 7).map((item) => item.checkpointId));
  const preMigration = eligible.find((item) => item.kind === 'pre_migration');
  if (preMigration) keep.add(preMigration.checkpointId);
  return { keep: ordered.filter((item) => keep.has(item.checkpointId)).map((item) => item.checkpointId),
    retire: ordered.filter((item) => !keep.has(item.checkpointId)).map((item) => item.checkpointId) };
}
