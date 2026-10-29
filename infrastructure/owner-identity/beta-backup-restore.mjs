import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { inspectBackupFile, validateBackupInventory, verifyBackupIntegrity } from './beta-backup-inventory.mjs';
import { openSealedCheckpointPayload } from './beta-backup-sealed-bundle.mjs';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOST_JOB_ID = /^[a-f0-9]{32}$/;
const REPORT_RETENTION_SECONDS = 2_592_000;
const OFFICIAL_MANIFEST_PATH = 'evidence/official-evidence-manifest.json';
const OFFICIAL_FILE_PREFIX = 'evidence/official/';
const RESTORED_OFFICIAL_SCHEMA = 'beta-restored-official-evidence/v1';
const MAX_OFFICIAL_FILE_COUNT = 4096;
const MAX_OFFICIAL_FILE_BYTES = 64 * 1024 * 1024;
const MAX_OFFICIAL_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const BINDING_HASHES = ['bonusGrantOperationsSha256', 'runOperationReceiptsSha256', 'runGenerationReceiptsSha256', 'reportOperationReceiptsSha256'];
const BINDING_COUNTS = ['bonusGrantOperationCount', 'runOperationReceiptCount', 'runGenerationReceiptCount', 'reportOperationReceiptCount'];

function fail(code) { throw new Error(`beta_backup_restore_${code}`); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function safeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') || isAbsolute(value) ||
      /^[A-Za-z]:/.test(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) fail('unsafe_bundle_path');
  return value;
}
function within(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function parseIso(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail('timestamp_invalid');
  return Date.parse(value);
}
async function inspectPathChain(path, expectedType, { privateMode = false } = {}) {
  const absolute = resolve(path);
  let current = parse(absolute).root;
  const parts = relative(current, absolute).split(sep).filter(Boolean);
  let finalInfo;
  for (let index = 0; index < parts.length; index += 1) {
    current = resolve(current, parts[index]);
    const info = await lstat(current).catch(() => fail('required_path_missing'));
    if (info.isSymbolicLink()) fail('path_symlink');
    if (index < parts.length - 1 && !info.isDirectory()) fail('path_parent_not_directory');
    if (index === parts.length - 1) finalInfo = info;
  }
  if (!finalInfo || (expectedType === 'directory' ? !finalInfo.isDirectory() : !finalInfo.isFile())) fail('path_type_invalid');
  if (privateMode && process.platform !== 'win32' && (finalInfo.mode & 0o077) !== 0) fail('external_secret_permissions');
  return { info: finalInfo, canonicalPath: await realpath(absolute) };
}
async function listFiles(root, relativeRoot = '') {
  const rows = [];
  for (const entry of await readdir(resolve(root, relativeRoot), { withFileTypes: true })) {
    const childRelative = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    const info = await lstat(resolve(root, childRelative));
    if (info.isSymbolicLink()) fail('bundle_symlink');
    if (info.isDirectory()) rows.push(...await listFiles(root, childRelative));
    else if (info.isFile()) rows.push(childRelative);
    else fail('bundle_special_file');
  }
  return rows.sort();
}
async function readJson(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { fail('json_invalid'); }
}
function validateClosure(value) {
  if (!value || value.schemaVersion !== 'beta-report-closure-state/v1' ||
      !(value.betaEndedAt === null || (typeof value.betaEndedAt === 'string' && Number.isFinite(Date.parse(value.betaEndedAt)) &&
        new Date(value.betaEndedAt).toISOString() === value.betaEndedAt)) || !HASH.test(value.sourceEvidenceSha256 ?? '') ||
      Object.keys(value).some((key) => !['schemaVersion', 'betaEndedAt', 'sourceEvidenceSha256'].includes(key))) fail('authoritative_closure_invalid');
  return value;
}
function validateBindings(bindings) {
  if (!bindings || BINDING_HASHES.some((key) => !HASH.test(bindings[key] ?? '')) ||
      BINDING_COUNTS.some((key) => !Number.isSafeInteger(bindings[key]) || bindings[key] < 0)) fail('operation_bindings_invalid');
  return bindings;
}
function validateObserverSnapshot(value, databaseName) {
  const identity = value?.observerIdentity;
  if (!identity || identity.databaseRole !== 'oid_observer' || identity.databaseName !== databaseName || identity.transactionReadOnly !== 'on') {
    fail('read_only_observer_identity_mismatch');
  }
  for (const key of ['databaseTotalsSha256', 'financialStateSha256', 'benchmarkStateSha256', 'reportStateSha256',
    'reportRateLimitStateSha256', 'controlOperationalStateSha256']) {
    if (!HASH.test(value[key] ?? '')) fail('observer_snapshot_hash_missing');
  }
  validateBindings(value.operationBindings);
  if (!Array.isArray(value.imageFiles) || !Array.isArray(value.reportDeletionReceipts) ||
      !Number.isSafeInteger(value.reportCount) || value.reportCount < 0 ||
      !Number.isSafeInteger(value.uploadCount) || value.uploadCount < 0) fail('observer_report_snapshot_invalid');
  return value;
}
function validateOriginalIds(value) {
  const ids = value?.originalIds;
  const uuidList = (list) => Array.isArray(list) && list.every((id) => UUID.test(id)) && new Set(list).size === list.length;
  const operationList = (list) => Array.isArray(list) && list.every((id) => typeof id === 'string' && /^[A-Za-z0-9_-]{12,128}$/.test(id)) && new Set(list).size === list.length;
  if (!ids || !uuidList(ids.completedRunIds) || !uuidList(ids.queuedInterruptedUnknownRunIds) ||
      !operationList(ids.operationIds) || !operationList(ids.bonusGrantOperationIds) || !operationList(ids.reportOperationIds)) fail('original_ids_invalid');
  return ids;
}
async function verifySealedBundleFileSet(bundleRoot, inventoryPath, inventory) {
  const expected = ['checkpoint.bundle.enc', 'inventory.json'];
  if (canonical(await listFiles(bundleRoot)) !== canonical(expected)) fail('bundle_file_set_mismatch');
  const inventoryInfo = await inspectPathChain(inventoryPath, 'file');
  if (!within(bundleRoot, inventoryInfo.canonicalPath) || inventoryInfo.canonicalPath !== resolve(bundleRoot, 'inventory.json')) fail('inventory_path_mismatch');
  const row = inventory.files.find((item) => item.kind === 'sealed_bundle' && item.path === 'checkpoint.bundle.enc');
  if (!row) fail('sealed_bundle_missing');
  return { artifact: row, inventorySha256: hash(await readFile(inventoryPath)) };
}
async function writeClosureCopy(path, closure) {
  const bytes = Buffer.from(`${JSON.stringify(closure)}\n`, 'utf8');
  const handle = await import('node:fs/promises').then(({ open }) => open(path, 'wx', 0o600)).catch(() => fail('restore_closure_copy_failed'));
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  return hash(bytes);
}
export async function restoreOfficialEvidenceFiles({ payloadRoot, payloadManifest, restoreRoot, restoreDatabaseName,
  checkpointId, sourceBuildSha256, expectedManifestSha256, expectedSource }) {
  if (!isAbsolute(payloadRoot ?? '') || !isAbsolute(restoreRoot ?? '') ||
      !/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '') || !UUID.test(checkpointId ?? '') ||
      !HASH.test(sourceBuildSha256 ?? '') || !HASH.test(expectedManifestSha256 ?? '') ||
      !payloadManifest || !Array.isArray(payloadManifest.files) || !expectedSource ||
      typeof expectedSource.profile !== 'string' || !expectedSource.profile ||
      !Number.isSafeInteger(expectedSource.runIdCount) || expectedSource.runIdCount < 1 ||
      !HASH.test(expectedSource.runIdsSha256 ?? '')) fail('official_evidence_restore_input_invalid');
  const payloadInfo = await inspectPathChain(payloadRoot, 'directory');
  const cloneInfo = await inspectPathChain(restoreRoot, 'directory');
  const canonicalPayloadRoot = payloadInfo.canonicalPath;
  const canonicalRestoreRoot = cloneInfo.canonicalPath;
  const manifestPath = resolve(canonicalPayloadRoot, ...OFFICIAL_MANIFEST_PATH.split('/'));
  const manifestFileInfo = await inspectPathChain(manifestPath, 'file');
  if (!within(canonicalPayloadRoot, manifestFileInfo.canonicalPath) ||
      manifestFileInfo.canonicalPath !== manifestPath) fail('official_evidence_manifest_path_invalid');
  const manifestBytes = await readFile(manifestPath);
  const manifestSha256 = hash(manifestBytes);
  if (manifestSha256 !== expectedManifestSha256 || manifestBytes.length > 16 * 1024 * 1024) {
    fail('official_evidence_manifest_hash_invalid');
  }
  let official;
  try { official = JSON.parse(manifestBytes.toString('utf8')); }
  catch { fail('official_evidence_manifest_invalid'); }
  if (!official || official.schemaVersion !== 'beta-official-evidence-source/v1' ||
      official.sourceProfile !== expectedSource.profile || official.sourceBuildSha256 !== sourceBuildSha256 ||
      !Array.isArray(official.runIds) || official.runIds.length !== expectedSource.runIdCount ||
      hash(Buffer.from(canonical(official.runIds))) !== expectedSource.runIdsSha256 ||
      !Array.isArray(official.files) || official.files.length < 1 ||
      official.files.length > MAX_OFFICIAL_FILE_COUNT) fail('official_evidence_manifest_binding_invalid');
  const payloadRows = new Map(payloadManifest.files.map((row) => [row?.path, row]));
  const manifestRow = payloadRows.get(OFFICIAL_MANIFEST_PATH);
  if (!manifestRow || manifestRow.kind !== 'evidence' || manifestRow.bytes !== manifestBytes.length ||
      manifestRow.sha256 !== manifestSha256) fail('official_evidence_payload_manifest_binding_invalid');
  const expectedPayloadPaths = [];
  const seen = new Set();
  const files = [];
  let totalBytes = 0;
  for (const row of official.files) {
    if (!row || typeof row.path !== 'string' || !row.path.startsWith(OFFICIAL_FILE_PREFIX) ||
        !Number.isSafeInteger(row.bytes) || row.bytes < 0 || row.bytes > MAX_OFFICIAL_FILE_BYTES ||
        !HASH.test(row.sha256 ?? '') || typeof row.role !== 'string' ||
        !/^[a-z][a-z0-9_-]{1,63}$/.test(row.role)) fail('official_evidence_file_metadata_invalid');
    const relativePath = safeRelative(row.path.slice(OFFICIAL_FILE_PREFIX.length));
    const collision = relativePath.toLocaleLowerCase('en-US');
    if (seen.has(collision)) fail('official_evidence_duplicate_path');
    seen.add(collision);
    totalBytes += row.bytes;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_OFFICIAL_TOTAL_BYTES) fail('official_evidence_total_bytes_invalid');
    const payloadRow = payloadRows.get(row.path);
    if (!payloadRow || payloadRow.kind !== 'evidence' || payloadRow.bytes !== row.bytes || payloadRow.sha256 !== row.sha256) {
      fail('official_evidence_payload_file_binding_invalid');
    }
    expectedPayloadPaths.push(row.path);
    files.push({ path: 'official-evidence/' + relativePath, relativePath, role: row.role, bytes: row.bytes, sha256: row.sha256 });
  }
  const payloadOfficialPaths = payloadManifest.files.filter((row) =>
    row?.kind === 'evidence' && typeof row.path === 'string' && row.path.startsWith(OFFICIAL_FILE_PREFIX))
    .map((row) => row.path).sort();
  if (canonical(payloadOfficialPaths) !== canonical([...expectedPayloadPaths].sort())) {
    fail('official_evidence_payload_file_set_invalid');
  }
  const officialEvidenceRoot = resolve(canonicalRestoreRoot, 'official-evidence');
  if (!within(canonicalRestoreRoot, officialEvidenceRoot) || officialEvidenceRoot === canonicalRestoreRoot) {
    fail('official_evidence_clone_root_invalid');
  }
  await mkdir(officialEvidenceRoot, { recursive: false, mode: 0o700 });
  const officialRootInfo = await inspectPathChain(officialEvidenceRoot, 'directory');
  if (officialRootInfo.canonicalPath !== officialEvidenceRoot) fail('official_evidence_clone_root_invalid');
  for (const row of official.files) {
    const relativePath = row.path.slice(OFFICIAL_FILE_PREFIX.length);
    const safeRelativePath = safeRelative(relativePath);
    const sourcePath = resolve(canonicalPayloadRoot, ...row.path.split('/'));
    if (!within(canonicalPayloadRoot, sourcePath)) fail('official_evidence_source_path_invalid');
    const sourceInfo = await inspectPathChain(sourcePath, 'file');
    if (sourceInfo.canonicalPath !== sourcePath) fail('official_evidence_source_path_invalid');
    const bytes = await readFile(sourcePath);
    if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) fail('official_evidence_source_hash_mismatch');
    const targetPath = resolve(officialEvidenceRoot, ...safeRelativePath.split('/'));
    if (!within(officialEvidenceRoot, targetPath) || targetPath === officialEvidenceRoot) fail('official_evidence_target_path_invalid');
    const targetParent = resolve(targetPath, '..');
    await mkdir(targetParent, { recursive: true, mode: 0o700 });
    const targetParentInfo = await inspectPathChain(targetParent, 'directory');
    if (!within(officialEvidenceRoot, targetParentInfo.canonicalPath)) fail('official_evidence_target_path_invalid');
    const handle = await open(targetPath, 'wx', 0o600).catch(() => fail('official_evidence_target_create_failed'));
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    const observed = await inspectBackupFile(officialEvidenceRoot, safeRelativePath, 'evidence');
    if (observed.bytes !== row.bytes || observed.sha256 !== row.sha256) fail('official_evidence_clone_hash_mismatch');
  }
  const actualPaths = await listFiles(officialEvidenceRoot);
  const expectedClonePaths = files.map((row) => row.relativePath).sort();
  if (canonical(actualPaths) !== canonical(expectedClonePaths)) fail('official_evidence_clone_file_set_invalid');
  const receiptRelativePath = 'operator/official-evidence-restore.json';
  const receiptPath = resolve(canonicalRestoreRoot, ...receiptRelativePath.split('/'));
  const operatorRoot = resolve(canonicalRestoreRoot, 'operator');
  const operatorInfo = await inspectPathChain(operatorRoot, 'directory');
  if (!within(canonicalRestoreRoot, operatorInfo.canonicalPath) || operatorInfo.canonicalPath !== operatorRoot) {
    fail('official_evidence_receipt_path_invalid');
  }
  const durableManifestRelativePath = 'operator/official-evidence-manifest.json';
  const durableManifestPath = resolve(canonicalRestoreRoot, ...durableManifestRelativePath.split('/'));
  const manifestHandle = await open(durableManifestPath, 'wx', 0o600).catch(() => fail('official_evidence_manifest_copy_create_failed'));
  try { await manifestHandle.writeFile(manifestBytes); await manifestHandle.sync(); } finally { await manifestHandle.close(); }
  const durableManifestProof = await inspectBackupFile(canonicalRestoreRoot, durableManifestRelativePath, 'evidence');
  if (durableManifestProof.bytes !== manifestBytes.length || durableManifestProof.sha256 !== manifestSha256) {
    fail('official_evidence_manifest_copy_hash_mismatch');
  }
  const receipt = { schemaVersion: RESTORED_OFFICIAL_SCHEMA, status: 'restored_verified',
    checkpointId, sourceBuildSha256, restoreDatabaseName, sourceManifestPath: OFFICIAL_MANIFEST_PATH,
    manifestPath: durableManifestRelativePath,
    manifestSha256, fileCount: files.length, totalBytes, files };
  const receiptBytes = Buffer.from(JSON.stringify(receipt) + '\n', 'utf8');
  const receiptHandle = await open(receiptPath, 'wx', 0o600).catch(() => fail('official_evidence_receipt_create_failed'));
  try { await receiptHandle.writeFile(receiptBytes); await receiptHandle.sync(); } finally { await receiptHandle.close(); }
  return { officialEvidenceRoot,
    officialEvidenceManifestPath: durableManifestRelativePath,
    verifiedOfficialEvidenceFiles: files,
    officialEvidenceRestoreReceipt: { path: receiptRelativePath, sha256: hash(receiptBytes), bytes: receiptBytes.length },
    officialEvidenceManifestSha256: manifestSha256 };
}
function safeRestoreFailureCode(error) {
  const match = /^beta_backup_restore_([a-z0-9_]+)$/.exec(String(error?.message ?? ''));
  return match?.[1] ?? 'restore_failed';
}
async function removeOwnedUnservedRestoreRoot({ restoreParent, restoreRoot, restoreDatabaseName }) {
  if (!/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '') || !isAbsolute(restoreParent ?? '') ||
      !isAbsolute(restoreRoot ?? '')) fail('failure_cleanup_identity_invalid');
  const parent = (await inspectPathChain(restoreParent, 'directory')).canonicalPath;
  const expected = resolve(parent, restoreDatabaseName);
  if (resolve(restoreRoot) !== expected || !within(parent, expected)) fail('failure_cleanup_identity_invalid');
  const root = await inspectPathChain(expected, 'directory');
  if (root.canonicalPath !== expected) fail('failure_cleanup_identity_invalid');
  await rm(expected, { recursive: true, force: false });
  const remaining = await lstat(expected).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (remaining) fail('failure_cleanup_root_remains');
  return 'removed';
}
export async function removeOwnedUnsealedRestoreRoot({ restoreParent, restoreRoot, unsealedRoot, restoreDatabaseName }) {
  if (!/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '') || !isAbsolute(restoreParent ?? '') ||
      !isAbsolute(restoreRoot ?? '') || !isAbsolute(unsealedRoot ?? '')) fail('unsealed_cleanup_identity_invalid');
  const parent = (await inspectPathChain(restoreParent, 'directory')).canonicalPath;
  const expectedRoot = resolve(parent, restoreDatabaseName);
  if (resolve(restoreRoot) !== expectedRoot || !within(parent, expectedRoot)) fail('unsealed_cleanup_identity_invalid');
  const root = await inspectPathChain(expectedRoot, 'directory');
  if (root.canonicalPath !== expectedRoot || resolve(unsealedRoot) !== resolve(expectedRoot, 'unsealed')) {
    fail('unsealed_cleanup_identity_invalid');
  }
  let info = await lstat(unsealedRoot).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (!info) return 'already_absent';
  if (info.isSymbolicLink() || !info.isDirectory()) fail('unsealed_cleanup_path_invalid');
  const unsealed = await inspectPathChain(unsealedRoot, 'directory');
  if (unsealed.canonicalPath !== resolve(expectedRoot, 'unsealed')) fail('unsealed_cleanup_path_invalid');
  await rm(unsealed.canonicalPath, { recursive: true, force: false });
  info = await lstat(unsealedRoot).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (info) fail('unsealed_cleanup_path_remains');
  return 'removed';
}
async function writeSafeRestoreFailureReceipt({ restoreParent, checkpointId, restoreDatabaseName,
  reasonCode, restoreRootDisposition, databaseDisposition }) {
  if (!isAbsolute(restoreParent ?? '') || !UUID.test(checkpointId ?? '') ||
      !/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '')) fail('failure_receipt_identity_invalid');
  const parent = (await inspectPathChain(restoreParent, 'directory')).canonicalPath;
  const failureRoot = resolve(parent, 'failed-restores');
  if (!within(parent, failureRoot)) fail('failure_receipt_path_invalid');
  let rootInfo = await lstat(failureRoot).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (!rootInfo) await mkdir(failureRoot, { recursive: false, mode: 0o700 });
  const verifiedRoot = await inspectPathChain(failureRoot, 'directory');
  if (verifiedRoot.canonicalPath !== failureRoot || !within(parent, verifiedRoot.canonicalPath)) fail('failure_receipt_path_invalid');
  rootInfo = verifiedRoot.info;
  if (rootInfo.isSymbolicLink()) fail('failure_receipt_path_invalid');
  const receipt = { schemaVersion: 'beta-combined-restore-failure/v1', status: 'failed_unserved', checkpointId,
    restoreDatabaseName, reasonCode, restoreRootDisposition, databaseDisposition, failedAt: new Date().toISOString() };
  const path = resolve(failureRoot, `${restoreDatabaseName}.json`);
  const bytes = Buffer.from(`${JSON.stringify(receipt)}\n`, 'utf8');
  const handle = await open(path, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  return { path, sha256: hash(bytes), bytes: bytes.length };
}
/** Remove only the uniquely-created, still-unserved private restore root and retain a secret-free failure identity. */
export async function cleanupUnservedRestoreArtifacts({ restoreParent, restoreRoot, restoreRootCreated, checkpointId,
  restoreDatabaseName, reasonCode, databaseDisposition = 'not_created_or_unknown' }) {
  if (!UUID.test(checkpointId ?? '') || !/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '') ||
      !/^[a-z0-9_]{1,80}$/.test(reasonCode ?? '') ||
      !['not_created_or_unknown', 'preserved_unserved_for_inspection'].includes(databaseDisposition)) {
    fail('failure_receipt_identity_invalid');
  }
  let restoreRootDisposition = restoreRootCreated ? 'retained_cleanup_failed' : 'not_created';
  if (restoreRootCreated) {
    try { restoreRootDisposition = await removeOwnedUnservedRestoreRoot({ restoreParent, restoreRoot, restoreDatabaseName }); }
    catch { restoreRootDisposition = 'retained_cleanup_failed'; }
  }
  let failureReceipt = null;
  try {
    failureReceipt = await writeSafeRestoreFailureReceipt({ restoreParent, checkpointId, restoreDatabaseName,
      reasonCode, restoreRootDisposition, databaseDisposition });
  } catch { /* Keep the safe failure identity available to the caller if disk journaling is unavailable. */ }
  return { schemaVersion: 'beta-combined-restore-failure/v1', checkpointId, restoreDatabaseName, reasonCode,
    restoreRootDisposition, databaseDisposition,
    failureReceipt: failureReceipt ? { path: failureReceipt.path, sha256: failureReceipt.sha256 } : null };
}
function bindingSnapshotHash(snapshot) { return canonical(snapshot.operationBindings); }

/** Validate and project the host broker receipts that created and populated a fresh restore DB. */
export function validateRestoreReceiptPair({ restoreDatabaseName, checkpointId, databaseDumpSha256,
  creationReceipt, restoreReceipt }) {
  if (!/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName ?? '') || !UUID.test(checkpointId ?? '') ||
      !HASH.test(databaseDumpSha256 ?? '') || !creationReceipt || !restoreReceipt ||
      creationReceipt.status !== 'complete' || creationReceipt.kind !== 'create_restore_database' ||
      !HOST_JOB_ID.test(creationReceipt.jobId ?? '') || creationReceipt.creationJobId !== creationReceipt.jobId ||
      creationReceipt.databaseName !== restoreDatabaseName || creationReceipt.checkpointId !== checkpointId ||
      creationReceipt.createdFresh !== true || restoreReceipt.status !== 'restored' ||
      restoreReceipt.kind !== 'pg_restore' || !HOST_JOB_ID.test(restoreReceipt.jobId ?? '') ||
      restoreReceipt.jobId === creationReceipt.jobId || restoreReceipt.databaseName !== restoreDatabaseName ||
      restoreReceipt.checkpointId !== checkpointId || restoreReceipt.creationJobId !== creationReceipt.jobId ||
      restoreReceipt.dumpSha256 !== databaseDumpSha256 || restoreReceipt.restored !== true) {
    fail('restore_receipt_pair_invalid');
  }
  return {
    creationReceipt: { status: creationReceipt.status, kind: creationReceipt.kind, jobId: creationReceipt.jobId,
      databaseName: creationReceipt.databaseName, checkpointId: creationReceipt.checkpointId,
      creationJobId: creationReceipt.creationJobId, createdFresh: creationReceipt.createdFresh },
    restoreReceipt: { status: restoreReceipt.status, kind: restoreReceipt.kind, jobId: restoreReceipt.jobId,
      databaseName: restoreReceipt.databaseName, checkpointId: restoreReceipt.checkpointId,
      creationJobId: restoreReceipt.creationJobId, dumpSha256: restoreReceipt.dumpSha256, restored: restoreReceipt.restored },
  };
}

/** Check the runner's real same-ID retries against the before/after independent DB observations. */
export function verifyCombinedRestoreRetryProof({ restoredBaseline, before, after, retryProof, operationBindings, originalIds, retentionExpired }) {
  if (!restoredBaseline || !before || !after || restoredBaseline.observerIdentity?.databaseName !== before.observerIdentity?.databaseName ||
      before.observerIdentity?.databaseName !== after.observerIdentity?.databaseName) fail('retry_observation_identity_mismatch');
  validateObserverSnapshot(restoredBaseline, before.observerIdentity.databaseName);
  validateObserverSnapshot(before, before.observerIdentity.databaseName);
  validateObserverSnapshot(after, before.observerIdentity.databaseName);
  validateBindings(operationBindings);
  if (bindingSnapshotHash(restoredBaseline) !== canonical(operationBindings) ||
      bindingSnapshotHash(before) !== canonical(operationBindings) || bindingSnapshotHash(after) !== canonical(operationBindings)) {
    fail('retry_operation_bindings_changed');
  }
  const businessStateKeys = ['financialStateSha256', 'benchmarkStateSha256', 'reportStateSha256'];
  for (const key of businessStateKeys) {
    if (restoredBaseline[key] !== before[key] || before[key] !== after[key]) fail('retry_state_changed');
  }
  const proof = retryProof;
  if (!proof || proof.status !== 'verified' || canonical(proof.receiptBindings) !== canonical(operationBindings) ||
      canonical(proof.completedRunIds) !== canonical(originalIds?.completedRunIds) ||
      canonical(proof.queuedInterruptedUnknownRunIds) !== canonical(originalIds?.queuedInterruptedUnknownRunIds) ||
      proof.noNewGrantOrLedgerEffects !== true || proof.noNewRunTaskOrActionEffects !== true ||
      (retentionExpired ? proof.reportOperationDisposition !== 'expired_content_not_replayed'
        : proof.reportOperationDisposition !== 'same_receipts_replayed')) fail('original_operation_reconciliation_failed');
  if (retentionExpired && (after.reportCount !== 0 || after.uploadCount !== 0 || after.imageFiles.length !== 0)) fail('expired_support_resurrected_by_retry');
  return { status: 'verified', receiptBindings: operationBindings, completedRunCount: originalIds.completedRunIds.length,
    unresolvedRunCount: originalIds.queuedInterruptedUnknownRunIds.length,
    operationCount: originalIds.operationIds.length, noNewFinancialEffects: true, noNewBenchmarkEffects: true,
    noNewReportBusinessEffects: true,
    controlOperationalState: { beforeUiSha256: restoredBaseline.controlOperationalStateSha256,
      afterUiStartSha256: before.controlOperationalStateSha256, afterRetrySha256: after.controlOperationalStateSha256,
      changedFromRestoreBaseline: restoredBaseline.controlOperationalStateSha256 !== before.controlOperationalStateSha256,
      changedDuringRetryWindow: before.controlOperationalStateSha256 !== after.controlOperationalStateSha256 },
    reportRateLimitState: { beforeUiSha256: restoredBaseline.reportRateLimitStateSha256,
      afterUiStartSha256: before.reportRateLimitStateSha256, afterRetrySha256: after.reportRateLimitStateSha256,
      changedFromRestoreBaseline: restoredBaseline.reportRateLimitStateSha256 !== before.reportRateLimitStateSha256,
      changedDuringRetryWindow: before.reportRateLimitStateSha256 !== after.reportRateLimitStateSha256 },
    retentionExpired, writesMayBeEnabled: false };
}

/** Restore to a fresh isolated database and private root. Return before the runner starts any API. */
export async function restoreCombinedCheckpoint({ source, checkpoint, restore, adapters, keyRecovery, now = new Date().toISOString(), retentionFixture = null }) {
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const nowMs = parseIso(now);
  if (!source || typeof source.databaseName !== 'string' || !/^[A-Za-z0-9_]{1,63}$/.test(source.databaseName) ||
      !checkpoint || !isAbsolute(checkpoint.bundleRoot ?? '') || !isAbsolute(checkpoint.externalKeyRecoveryPath ?? '') ||
      !isAbsolute(checkpoint.authoritativeClosurePath ?? '') || !restore || !isAbsolute(restore.restoreRoot ?? '') || !adapters || !keyRecovery ||
      typeof keyRecovery.recoverMaterial !== 'function') fail('input_invalid');
  for (const name of ['databaseExists', 'createRestoreDatabase', 'restoreDatabaseDump', 'restorePrivateFiles', 'observeReadOnly', 'cleanupExpiredClone']) {
    if (typeof adapters[name] !== 'function') fail(`adapter_${name}_missing`);
  }
  const bundleInfo = await inspectPathChain(checkpoint.bundleRoot, 'directory');
  const bundleRoot = bundleInfo.canonicalPath;
  const inventoryPath = resolve(bundleRoot, 'inventory.json');
  const inventory = await readJson(inventoryPath);
  validateBackupInventory(inventory);
  if (inventory.schemaVersion !== 'beta-backup-inventory/v2' || inventory.checkpointSource?.sourceDatabase !== source.databaseName ||
      inventory.checkpointSource?.boundary !== 'admission_frozen_database_quiescent' ||
      !HASH.test(inventory.databaseTotalsSha256 ?? '') || canonical(inventory.operationBindings) !== canonical(inventory.checkpointSource.operationBindings)) {
    fail('combined_checkpoint_metadata_missing');
  }
  const artifactProof = await verifySealedBundleFileSet(bundleRoot, inventoryPath, inventory);
  const fileIntegrity = await verifyBackupIntegrity(bundleRoot, inventory);
  if (fileIntegrity.integrity !== 'passed' || fileIntegrity.writesMayBeEnabled !== false) fail('sealed_bundle_integrity_failed');
  const externalEnvelope = await inspectPathChain(checkpoint.externalKeyRecoveryPath, 'file', { privateMode: true });
  if (within(bundleRoot, externalEnvelope.canonicalPath)) fail('external_key_must_be_separate');
  const externalEnvelopeBytes = await readFile(externalEnvelope.canonicalPath);
  if (!HASH.test(inventory.recoveryEnvelopeSha256 ?? '') || hash(externalEnvelopeBytes) !== inventory.recoveryEnvelopeSha256) {
    externalEnvelopeBytes.fill(0);
    fail('external_recovery_envelope_integrity_mismatch');
  }
  externalEnvelopeBytes.fill(0);
  const closureFile = await inspectPathChain(checkpoint.authoritativeClosurePath, 'file', { privateMode: true });
  if (within(bundleRoot, closureFile.canonicalPath)) fail('authoritative_closure_must_be_external');
  const authoritativeClosure = validateClosure(await readJson(closureFile.canonicalPath));
  if (inventory.betaEndedAt !== null && (authoritativeClosure.betaEndedAt === null ||
      parseIso(authoritativeClosure.betaEndedAt) < parseIso(inventory.betaEndedAt))) fail('authoritative_closure_regressed');
  let cloneClosure = authoritativeClosure;
  let syntheticHistoricalClosureFixture = null;
  if (retentionFixture !== null) {
    const allowedKeys = ['betaEndedAt', 'kind', 'sourceEvidenceSha256'];
    if (!retentionFixture || typeof retentionFixture !== 'object' || Array.isArray(retentionFixture) ||
        Object.keys(retentionFixture).sort().join(',') !== allowedKeys.join(',') ||
        retentionFixture.kind !== 'synthetic_historical_clone_31d' ||
        retentionFixture.sourceEvidenceSha256 !== authoritativeClosure.sourceEvidenceSha256) fail('retention_fixture_invalid');
    const fixtureAt = parseIso(retentionFixture.betaEndedAt);
    const fixtureAgeMs = nowMs - fixtureAt;
    if (fixtureAgeMs < 31 * 86_400_000 || fixtureAgeMs >= 32 * 86_400_000) fail('retention_fixture_age_invalid');
    cloneClosure = { ...authoritativeClosure, betaEndedAt: retentionFixture.betaEndedAt };
    syntheticHistoricalClosureFixture = { kind: retentionFixture.kind, betaEndedAt: retentionFixture.betaEndedAt,
      sourceEvidenceSha256: retentionFixture.sourceEvidenceSha256, sourceClosureUnchanged: true,
      scope: 'restored_clone_only_synthetic_history' };
  }
  const closureTimes = [inventory.betaEndedAt, authoritativeClosure.betaEndedAt, cloneClosure.betaEndedAt]
    .filter((value) => value !== null).map(parseIso);
  const effectiveBetaEndedAt = closureTimes.length ? new Date(Math.min(...closureTimes)).toISOString() : null;
  const retentionExpired = effectiveBetaEndedAt !== null && nowMs >= parseIso(effectiveBetaEndedAt) + REPORT_RETENTION_SECONDS * 1000;
  const restoreDatabaseName = `oid_restore_${randomUUID().replaceAll('-', '')}`;
  if (!/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName)) fail('restore_database_name_invalid');
  let restoredMaterial;
  let restoreParent;
  let restoreRoot;
  let privateDataDir;
  let unsealedRoot;
  let closureStatePath;
  let closureCopySha256;
  let payload;
  let originalIds;
  let fileRestore;
  let officialEvidenceRestore;
  let beforeRetention;
  let afterRetention;
  let cloneCleanup;
  let restoreRootCreated = false;
  let creationReceipt = null;
  const sealed = inventory.files[0];
  try {
    restoredMaterial = await keyRecovery.recoverMaterial({ checkpointId: inventory.checkpointId,
      envelopePath: externalEnvelope.canonicalPath, envelopeSha256: inventory.recoveryEnvelopeSha256 });
    if (!restoredMaterial || !Buffer.isBuffer(restoredMaterial.bundleKey) || restoredMaterial.bundleKey.length !== 32 ||
        !restoredMaterial.runtimeSecrets || typeof restoredMaterial.runtimeSecrets !== 'object') fail('external_recovery_material_invalid');
    restoreParent = (await inspectPathChain(restore.restoreRoot, 'directory')).canonicalPath;
    restoreRoot = resolve(restoreParent, restoreDatabaseName);
    if (!within(restoreParent, restoreRoot)) fail('restore_root_escape');
    await mkdir(restoreRoot, { recursive: false, mode: 0o700 });
    restoreRootCreated = true;
    privateDataDir = resolve(restoreRoot, 'private-data');
    const operatorDir = resolve(restoreRoot, 'operator');
    unsealedRoot = resolve(restoreRoot, 'unsealed');
    await mkdir(privateDataDir, { recursive: false, mode: 0o700 });
    await mkdir(operatorDir, { recursive: false, mode: 0o700 });
    closureStatePath = resolve(operatorDir, 'authoritative-closure.json');
    closureCopySha256 = await writeClosureCopy(closureStatePath, cloneClosure);
    payload = await openSealedCheckpointPayload({ encryptedPath: resolve(bundleRoot, sealed.path),
      expectedEncryptedSha256: sealed.sha256, expectedEncryptedBytes: sealed.bytes, bundleRoot,
      destinationRoot: unsealedRoot, checkpointId: inventory.checkpointId,
      externalKeyRecoveryPath: externalEnvelope.canonicalPath, recoverKey: async () => restoredMaterial.bundleKey });
    if (payload.status !== 'authenticated' || payload.payloadManifestSha256 !== inventory.payloadManifestSha256) {
      fail('sealed_payload_manifest_mismatch');
    }
    const sourceBefore = await readJson(resolve(unsealedRoot, 'evidence/source-before.json'));
    const sourceAfter = await readJson(resolve(unsealedRoot, 'evidence/source-after.json'));
    const reconciliation = await readJson(resolve(unsealedRoot, 'evidence/reconciliation.json'));
    originalIds = validateOriginalIds(sourceBefore);
    validateOriginalIds(sourceAfter);
    if (sourceBefore.snapshotBoundaryId !== inventory.checkpointSource.snapshotBoundaryId ||
        sourceAfter.snapshotBoundaryId !== inventory.checkpointSource.snapshotBoundaryId ||
        sourceBefore.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        sourceAfter.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        reconciliation.sourceStable !== true || reconciliation.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        reconciliation.sourceBuildSha256 !== inventory.sourceBuildSha256 ||
        canonical(reconciliation.operationBindings) !== canonical(inventory.operationBindings)) fail('sealed_source_evidence_mismatch');
    const dumpPath = resolve(unsealedRoot, 'database.dump');
    const dumpRow = payload.manifest.files.find((row) => row.kind === 'database' && row.path === 'database.dump');
    if (!dumpRow) fail('sealed_database_dump_missing');
    const existing = await adapters.databaseExists({ databaseName: restoreDatabaseName });
    if (existing !== false) fail('restore_database_already_exists');
    creationReceipt = await adapters.createRestoreDatabase({ databaseName: restoreDatabaseName, checkpointId: inventory.checkpointId });
    if (!creationReceipt || creationReceipt.status !== 'complete' || creationReceipt.kind !== 'create_restore_database' ||
        !HOST_JOB_ID.test(creationReceipt.jobId ?? '') || creationReceipt.creationJobId !== creationReceipt.jobId ||
        creationReceipt.databaseName !== restoreDatabaseName || creationReceipt.checkpointId !== inventory.checkpointId ||
        creationReceipt.createdFresh !== true) fail('restore_database_creation_receipt_invalid');
    const dbRestore = await adapters.restoreDatabaseDump({ databaseName: restoreDatabaseName, dumpPath,
      dumpSha256: dumpRow.sha256, checkpointId: inventory.checkpointId, creationJobId: creationReceipt.creationJobId });
    const restoreReceipts = validateRestoreReceiptPair({ restoreDatabaseName, checkpointId: inventory.checkpointId,
      databaseDumpSha256: dumpRow.sha256, creationReceipt, restoreReceipt: dbRestore });
    fileRestore = await adapters.restorePrivateFiles({ payloadRoot: unsealedRoot, privateDataDir, restoreRoot });
    const officialEvidenceSource = inventory.checkpointSource.officialEvidenceSource;
    const expectedManifestSha256 = reconciliation.officialEvidenceManifestSha256;
    if (!officialEvidenceSource || !HASH.test(expectedManifestSha256 ?? '') ||
        (officialEvidenceSource.manifestPath !== undefined && officialEvidenceSource.manifestPath !== OFFICIAL_MANIFEST_PATH) ||
        (officialEvidenceSource.manifestSha256 !== undefined && officialEvidenceSource.manifestSha256 !== expectedManifestSha256)) {
      fail('official_evidence_checkpoint_manifest_binding_invalid');
    }
    officialEvidenceRestore = await restoreOfficialEvidenceFiles({ payloadRoot: unsealedRoot, payloadManifest: payload.manifest,
      restoreRoot, restoreDatabaseName, checkpointId: inventory.checkpointId,
      sourceBuildSha256: inventory.sourceBuildSha256, expectedManifestSha256, expectedSource: officialEvidenceSource });
    const imageRows = payload.manifest.files.filter((row) => row.kind === 'screenshot').map(({ path, bytes, sha256 }) => ({
      path, bytes, sha256 })).sort((a, b) => a.path.localeCompare(b.path));
    if (!fileRestore || fileRestore.status !== 'restored' || fileRestore.fileCount !== imageRows.length) fail('private_files_restore_not_verified');
    beforeRetention = validateObserverSnapshot(await adapters.observeReadOnly({ databaseName: restoreDatabaseName,
      privateDataDir, closureStatePath }), restoreDatabaseName);
    if (beforeRetention.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        canonical(beforeRetention.operationBindings) !== canonical(inventory.operationBindings) ||
        canonical(beforeRetention.imageFiles) !== canonical(imageRows)) fail('restored_database_or_images_mismatch');

    afterRetention = beforeRetention;
    cloneCleanup = { status: 'not_required', retentionExpired: false, sourceCheckpointId: inventory.checkpointId,
      restoreDatabaseName, financialStateBeforeSha256: beforeRetention.financialStateSha256,
      financialStateAfterSha256: beforeRetention.financialStateSha256, benchmarkStateBeforeSha256: beforeRetention.benchmarkStateSha256,
      benchmarkStateAfterSha256: beforeRetention.benchmarkStateSha256 };
    if (retentionExpired) {
      const cleanup = await adapters.cleanupExpiredClone({ databaseName: restoreDatabaseName, privateDataDir, closureStatePath,
        authoritativeClosure, effectiveBetaEndedAt, sourceCheckpointId: inventory.checkpointId });
      if (!cleanup || cleanup.status !== 'complete' || cleanup.sourceCheckpointId !== inventory.checkpointId ||
          cleanup.restoreDatabaseName !== restoreDatabaseName || !HASH.test(cleanup.cleanupReceiptSha256 ?? '') ||
          cleanup.reportsAfter !== 0 || cleanup.uploadsAfter !== 0 || cleanup.remainingImageFiles !== 0 ||
          cleanup.failedReportReceipts !== 0 || cleanup.pendingUploadGcReceipts !== 0 ||
          !HASH.test(cleanup.financialStateBeforeSha256 ?? '') || cleanup.financialStateBeforeSha256 !== cleanup.financialStateAfterSha256 ||
          !HASH.test(cleanup.benchmarkStateBeforeSha256 ?? '') || cleanup.benchmarkStateBeforeSha256 !== cleanup.benchmarkStateAfterSha256) {
        fail('expired_support_purge_incomplete');
      }
      afterRetention = validateObserverSnapshot(await adapters.observeReadOnly({ databaseName: restoreDatabaseName,
        privateDataDir, closureStatePath }), restoreDatabaseName);
      if (afterRetention.reportCount !== 0 || afterRetention.uploadCount !== 0 || afterRetention.imageFiles.length !== 0 ||
          afterRetention.financialStateSha256 !== beforeRetention.financialStateSha256 ||
          afterRetention.benchmarkStateSha256 !== beforeRetention.benchmarkStateSha256 ||
          afterRetention.reportDeletionReceipts.some((receipt) => receipt.status !== 'complete')) fail('expired_support_purge_observer_mismatch');
      cloneCleanup = { status: 'complete', retentionExpired: true, sourceCheckpointId: inventory.checkpointId,
        restoreDatabaseName, cleanupReceiptSha256: cleanup.cleanupReceiptSha256,
        reportsDeleted: cleanup.reportsDeleted, uploadsCleaned: cleanup.uploadsCleaned,
        reportStateBeforeSha256: cleanup.reportStateBeforeSha256, reportStateAfterSha256: cleanup.reportStateAfterSha256,
        financialStateBeforeSha256: cleanup.financialStateBeforeSha256, financialStateAfterSha256: cleanup.financialStateAfterSha256,
        benchmarkStateBeforeSha256: cleanup.benchmarkStateBeforeSha256, benchmarkStateAfterSha256: cleanup.benchmarkStateAfterSha256 };
    }
    await removeOwnedUnsealedRestoreRoot({ restoreParent, restoreRoot, unsealedRoot, restoreDatabaseName });
    const finishedMs = Date.now();
    const runtimeSecrets = restoredMaterial.runtimeSecrets;
    restoredMaterial.runtimeSecrets = null;
    restoredMaterial.bundleKey.fill(0);
    let secretsTaken = false;
    const result = {
      schemaVersion: 'beta-combined-restore/v2', status: 'verified_unserved',
      boundary: 'fresh_isolated_restore_database_and_private_root', checkpointId: inventory.checkpointId,
      sourceDatabase: source.databaseName, restoreDatabaseName, restoreRoot, captureIsolationRoot: restoreRoot,
      privateDataDir, closureStatePath,
      checkpoint: { inventorySha256: artifactProof.inventorySha256, databaseTotalsSha256: inventory.databaseTotalsSha256,
        sourceBuildSha256: inventory.sourceBuildSha256, capturedAt: inventory.capturedAt,
        operationBindings: inventory.operationBindings, payloadManifestSha256: payload.payloadManifestSha256,
        payloadFileCount: payload.extractedFileCount, databaseDumpSha256: dumpRow.sha256,
        officialEvidenceManifestSha256: officialEvidenceRestore.officialEvidenceManifestSha256 },
      officialEvidenceRoot: officialEvidenceRestore.officialEvidenceRoot,
      officialEvidenceManifestPath: officialEvidenceRestore.officialEvidenceManifestPath,
      verifiedOfficialEvidenceFiles: officialEvidenceRestore.verifiedOfficialEvidenceFiles,
      officialEvidenceRestoreReceipt: officialEvidenceRestore.officialEvidenceRestoreReceipt,
      officialEvidenceManifestSha256: officialEvidenceRestore.officialEvidenceManifestSha256,
      creationReceipt: restoreReceipts.creationReceipt, restoreReceipt: restoreReceipts.restoreReceipt,
      authoritativeClosure: { betaEndedAt: authoritativeClosure.betaEndedAt,
        sourceEvidenceSha256: authoritativeClosure.sourceEvidenceSha256 },
      cloneClosure: { betaEndedAt: cloneClosure.betaEndedAt, sourceEvidenceSha256: cloneClosure.sourceEvidenceSha256,
        copySha256: closureCopySha256, syntheticHistoricalFixture: syntheticHistoricalClosureFixture },
      originalIds, operationBindings: inventory.operationBindings,
      retention: { expired: retentionExpired, cloneCleanup, accessBeforeCleanup: false, restoredApplicationStarted: false,
        syntheticHistoricalClosureFixture },
      observations: { beforeRetention, afterRetention, fileRestore },
      timing: { startedAt, finishedAt: new Date(finishedMs).toISOString(), restoreElapsedMs: finishedMs - startedMs,
        localCheckpointAgeSecondsAtRestoreStart: Math.max(0, (startedMs - parseIso(inventory.capturedAt)) / 1000),
        checkpointLossWindowStatus: 'local_checkpoint_age_measured_target_rpo_unknown', failureDomain: 'same_host' },
      writesMayBeEnabled: false, targetHostAcceptance: 'not_run',
      takeRuntimeSecrets() {
        if (secretsTaken || !runtimeSecrets) fail('runtime_secrets_already_consumed');
        secretsTaken = true;
        const output = { ...runtimeSecrets };
        for (const key of Object.keys(runtimeSecrets)) runtimeSecrets[key] = '';
        return output;
      },
      takeRestoredDatabaseUrl() {
        if (typeof restore.databaseUrlForRestore !== 'function') fail('restore_database_url_provider_missing');
        return restore.databaseUrlForRestore({ databaseName: restoreDatabaseName });
      },
    };
    return result;
  } catch (error) {
    const reasonCode = safeRestoreFailureCode(error);
    const databaseDisposition = creationReceipt?.createdFresh === true ? 'preserved_unserved_for_inspection' : 'not_created_or_unknown';
    let failureIdentity = { schemaVersion: 'beta-combined-restore-failure/v1', checkpointId: inventory.checkpointId,
      restoreDatabaseName, reasonCode, restoreRootDisposition: restoreRootCreated ? 'retained_cleanup_failed' : 'not_created',
      databaseDisposition, failureReceipt: null };
    if (restoreParent) {
      try {
        failureIdentity = await cleanupUnservedRestoreArtifacts({ restoreParent, restoreRoot, restoreRootCreated,
          checkpointId: inventory.checkpointId, restoreDatabaseName, reasonCode, databaseDisposition });
      } catch { /* Preserve the original failure and its safe in-memory identity. */ }
    }
    if (restoredMaterial && Buffer.isBuffer(restoredMaterial.bundleKey)) restoredMaterial.bundleKey.fill(0);
    for (const key of Object.keys(restoredMaterial?.runtimeSecrets ?? {})) restoredMaterial.runtimeSecrets[key] = '';
    if (error && typeof error === 'object') {
      try {
        error.restoreFailure = failureIdentity;
      } catch { /* The safe receipt is best effort if an adapter returns a frozen error. */ }
    }
    throw error;
  }
}
