import { createHash } from 'node:crypto';
import { lstat, open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KINDS = new Set(['database', 'evidence', 'screenshot']);
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
  if (!value || value.schemaVersion !== 'beta-backup-inventory/v1' ||
      !UUID.test(value.checkpointId ?? '') ||
      !['daily', 'pre_migration', 'retention_sanitized'].includes(value.kind) ||
      value.failureDomain !== 'same_host' || !HASH.test(value.sourceBuildSha256 ?? '') ||
      !Array.isArray(value.files) || !Array.isArray(value.reportDeletionReceipts)) fail('invalid_inventory');
  const capturedAt = timestamp(value.capturedAt);
  if (!HASH.test(value.reconciliationEvidenceSha256 ?? '') || !HASH.test(value.databaseTotalsSha256 ?? '')) fail('missing_reconciliation_binding');
  const paths = new Set();
  let databases = 0;
  for (const row of value.files) {
    safeRelative(row.path);
    const collisionKey = row.path.toLowerCase();
    if (paths.has(collisionKey)) fail('duplicate_path');
    paths.add(collisionKey);
    if (!KINDS.has(row.kind) || !Number.isSafeInteger(row.bytes) || row.bytes < 0 || !HASH.test(row.sha256 ?? '')) fail('invalid_file');
    if (row.kind === 'database') { databases++; if (row.bytes === 0) fail('empty_database'); }
  }
  if (databases !== 1) fail('database_count');
  const ids = new Set();
  for (const receipt of value.reportDeletionReceipts) {
    if (!receipt || !UUID.test(receipt.reportId ?? '') || ids.has(receipt.reportId) ||
        !['pending', 'failed', 'complete'].includes(receipt.status)) fail('invalid_deletion_receipt');
    ids.add(receipt.reportId);
  }
  if (value.betaEndedAt !== null) {
    const expiry = timestamp(value.betaEndedAt) + 30 * DAY;
    if (capturedAt >= expiry && (value.kind !== 'retention_sanitized' ||
        value.files.some((file) => file.kind === 'screenshot') ||
        value.reportDeletionReceipts.some((receipt) => receipt.status !== 'complete') ||
        !HASH.test(value.sanitizationEvidenceSha256 ?? ''))) fail('expired_content_checkpoint');
  }
  return value;
}

/** Integrity only: this never establishes DB consistency, correct totals, or safe operation retries. */
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
  if (expired && (inventory.kind !== 'retention_sanitized' || inventory.files.some((file) => file.kind === 'screenshot') ||
      inventory.reportDeletionReceipts.some((receipt) => receipt.status !== 'complete') || !HASH.test(inventory.sanitizationEvidenceSha256 ?? ''))) {
    fail('restore_requires_report_purge');
  }
  for (const row of inventory.files) {
    const observed = await inspectBackupFile(root, row.path, row.kind);
    if (observed.sha256 !== row.sha256 || observed.bytes !== row.bytes) fail('file_integrity');
  }
  return {
    schemaVersion: 'beta-backup-file-verification/v1', checkpointId: inventory.checkpointId,
    verifiedAt: now, fileCount: inventory.files.length, checkpointAgeSeconds: (current - source) / 1000,
    reportRetentionExpired: expired, failureDomain: 'same_host', integrity: 'passed',
    restoreAcceptance: 'not_run', writesMayBeEnabled: false,
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
    return !expired || (item.kind === 'retention_sanitized' && !item.files.some((file) => file.kind === 'screenshot') &&
      item.reportDeletionReceipts.every((receipt) => receipt.status === 'complete') && HASH.test(item.sanitizationEvidenceSha256 ?? ''));
  });
  const keep = new Set(eligible.filter((item) => item.kind === 'daily' || item.kind === 'retention_sanitized').slice(0, 7).map((item) => item.checkpointId));
  const preMigration = eligible.find((item) => item.kind === 'pre_migration');
  if (preMigration) keep.add(preMigration.checkpointId);
  return { keep: ordered.filter((item) => keep.has(item.checkpointId)).map((item) => item.checkpointId),
    retire: ordered.filter((item) => !keep.has(item.checkpointId)).map((item) => item.checkpointId) };
}
