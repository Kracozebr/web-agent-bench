import { createHash, randomUUID } from 'node:crypto';
import { copyFile, lstat, mkdir, open, readFile, readdir, realpath, rename, rm } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { inspectBackupFile, validateBackupInventory, verifyBackupFiles } from './beta-backup-inventory.mjs';
import { sealCheckpointPayload } from './beta-backup-sealed-bundle.mjs';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLOSURE_SCHEMA = 'beta-report-closure-state/v1';
const ENCRYPTED_DUMP_HEADER = Buffer.from('BPC-SC022-DBENC-V1\n', 'ascii');
const DAY_SECONDS = 30 * 24 * 60 * 60;
const CHECKPOINT_SCHEMA_V2 = 'beta-backup-inventory/v2';

function fail(code) { throw new Error(`beta_backup_checkpoint_${code}`); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function safeRelative(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') || isAbsolute(value) ||
      /^[A-Za-z]:/.test(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) fail('unsafe_relative_path');
  return value;
}
function within(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function validIso(value) {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function requireHash(value, code) { if (typeof value !== 'string' || !HASH.test(value)) fail(code); return value; }

async function inspectPathChain(path, expectedType) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  const components = relative(root, absolute).split(sep).filter(Boolean);
  let finalInfo;
  for (let index = 0; index < components.length; index += 1) {
    current = resolve(current, components[index]);
    const info = await lstat(current).catch(() => fail('required_path_missing'));
    if (info.isSymbolicLink()) fail('path_symlink');
    const last = index === components.length - 1;
    if (!last && !info.isDirectory()) fail('path_parent_not_directory');
    if (last) finalInfo = info;
  }
  if (!finalInfo || (expectedType === 'directory' ? !finalInfo.isDirectory() : !finalInfo.isFile())) fail('path_type_invalid');
  return { info: finalInfo, canonicalPath: await realpath(absolute) };
}

async function assertNoSymlinkDirectory(path) {
  try { return (await inspectPathChain(path, 'directory')).canonicalPath; }
  catch (error) {
    if (String(error?.message ?? '').includes('required_path_missing')) fail('bundle_root_missing');
    if (String(error?.message ?? '').includes('path_type_invalid')) fail('bundle_root_not_directory');
    throw error;
  }
}

async function regularFile(path, { privateMode = false } = {}) {
  const result = await inspectPathChain(path, 'file');
  if (privateMode && process.platform !== 'win32' && (result.info.mode & 0o077) !== 0) fail('external_key_permissions');
  return result;
}

async function listRegularFiles(root, relativeRoot = '') {
  const directory = resolve(root, relativeRoot);
  const entries = await readdir(directory, { withFileTypes: true });
  const rows = [];
  for (const entry of entries) {
    const rel = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    const path = resolve(root, rel);
    const info = await lstat(path);
    if (info.isSymbolicLink()) fail('bundle_symlink');
    if (info.isDirectory()) rows.push(...await listRegularFiles(root, rel));
    else if (info.isFile()) rows.push(rel);
    else fail('bundle_special_file');
  }
  return rows.sort();
}

async function readJsonInside(root, relativePath) {
  const path = resolve(root, safeRelative(relativePath));
  if (!within(root, path)) fail('evidence_path_escape');
  await regularFile(path);
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { fail('evidence_json_invalid'); }
}

function assertOperationBindings(bindings) {
  const required = ['bonusGrantOperationsSha256', 'runOperationReceiptsSha256',
    'runGenerationReceiptsSha256', 'reportOperationReceiptsSha256'];
  const countKeys = ['bonusGrantOperationCount', 'runOperationReceiptCount',
    'runGenerationReceiptCount', 'reportOperationReceiptCount'];
  if (!bindings || typeof bindings !== 'object' || Array.isArray(bindings) ||
      required.some((key) => !HASH.test(bindings[key] ?? '')) ||
      countKeys.some((key) => !Number.isSafeInteger(bindings[key]) || bindings[key] < 0)) fail('operation_receipt_bindings_missing');
  return Object.fromEntries([...required, ...countKeys].map((key) => [key, bindings[key]]));
}

function assertStableSnapshots(before, after, input) {
  if (!before || !after || before.sourceDatabase !== input.sourceDatabase || after.sourceDatabase !== input.sourceDatabase ||
      before.snapshotBoundary !== 'admission_frozen_database_quiescent' ||
      after.snapshotBoundary !== before.snapshotBoundary ||
      typeof before.snapshotBoundaryId !== 'string' || before.snapshotBoundaryId.length < 16 ||
      after.snapshotBoundaryId !== before.snapshotBoundaryId ||
      !validIso(before.snapshotAt) || !validIso(after.snapshotAt) || Date.parse(after.snapshotAt) < Date.parse(before.snapshotAt) ||
      input.capturedAt !== before.snapshotAt) {
    fail('source_snapshot_boundary_invalid');
  }
  if (!before.tableFingerprints || typeof before.tableFingerprints !== 'object' || Array.isArray(before.tableFingerprints) ||
      !after.tableFingerprints || typeof after.tableFingerprints !== 'object' || Array.isArray(after.tableFingerprints)) {
    fail('source_table_fingerprints_missing');
  }
  const sourceBuild = requireHash(before.sourceBuildSha256, 'source_build_hash_missing');
  if (sourceBuild !== input.sourceBuildSha256 || after.sourceBuildSha256 !== sourceBuild) fail('source_build_changed');
  const totals = requireHash(before.databaseTotalsSha256, 'source_totals_hash_missing');
  if (after.databaseTotalsSha256 !== totals || canonical(before.tableFingerprints) !== canonical(after.tableFingerprints)) {
    fail('source_database_changed');
  }
  const beforeBindings = assertOperationBindings(before.operationBindings);
  const afterBindings = assertOperationBindings(after.operationBindings);
  if (canonical(beforeBindings) !== canonical(afterBindings)) fail('source_operation_receipts_changed');
  if (!Array.isArray(before.imageFiles) || !Array.isArray(after.imageFiles) || canonical(before.imageFiles) !== canonical(after.imageFiles)) {
    fail('source_image_set_changed');
  }
  if (!Array.isArray(before.reportDeletionReceipts) || canonical(before.reportDeletionReceipts) !== canonical(after.reportDeletionReceipts)) {
    fail('source_report_receipts_changed');
  }
  return { sourceBuildSha256: sourceBuild, databaseTotalsSha256: totals,
    operationBindings: beforeBindings, imageFiles: before.imageFiles, reportDeletionReceipts: before.reportDeletionReceipts };
}

function validateClosure(value) {
  if (!value || value.schemaVersion !== CLOSURE_SCHEMA ||
      !(value.betaEndedAt === null || validIso(value.betaEndedAt)) || !HASH.test(value.sourceEvidenceSha256 ?? '') ||
      Object.keys(value).some((key) => !['schemaVersion', 'betaEndedAt', 'sourceEvidenceSha256'].includes(key))) {
    fail('authoritative_closure_invalid');
  }
  return value;
}

async function writeJsonNew(path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let handle;
  try {
    handle = await open(path, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
  } catch {
    if (handle) await handle.close().catch(() => undefined);
    fail('immutable_inventory_write_failed');
  }
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

/** Finalize an already staged encrypted dump, committed images and official evidence into an immutable inventory. */
export async function finalizeBackupCheckpoint(input) {
  if (!input || !UUID.test(input.checkpointId ?? '') || !['daily', 'pre_migration', 'retention_sanitized'].includes(input.kind) ||
      typeof input.sourceDatabase !== 'string' || !/^[A-Za-z0-9_]{1,63}$/.test(input.sourceDatabase) ||
      !validIso(input.capturedAt) || !HASH.test(input.sourceBuildSha256 ?? '')) fail('input_invalid');
  const bundleRoot = await assertNoSymlinkDirectory(input.bundleRoot);
  const externalKeyPath = resolve(input.externalKeyRecoveryPath ?? '');
  if (!isAbsolute(input.externalKeyRecoveryPath ?? '') || within(bundleRoot, externalKeyPath)) fail('external_key_path_invalid');
  const externalKey = await regularFile(externalKeyPath, { privateMode: true });
  if (within(bundleRoot, externalKey.canonicalPath)) fail('external_key_path_invalid');
  const closurePath = resolve(input.authoritativeClosurePath ?? '');
  if (!isAbsolute(input.authoritativeClosurePath ?? '') || within(bundleRoot, closurePath)) fail('closure_path_invalid');
  const closureFile = await regularFile(closurePath, { privateMode: true });
  if (within(bundleRoot, closureFile.canonicalPath)) fail('closure_path_invalid');
  const closure = validateClosure(JSON.parse(await readFile(closurePath, 'utf8')));
  const closureSha256 = sha256(await readFile(closurePath));
  if (closure.betaEndedAt !== input.betaEndedAt || closureSha256 !== input.authoritativeClosureSha256) fail('closure_changed_during_checkpoint');

  const sourceBeforePath = safeRelative(input.sourceBeforePath ?? 'evidence/source-before.json');
  const sourceAfterPath = safeRelative(input.sourceAfterPath ?? 'evidence/source-after.json');
  const reconciliationPath = safeRelative(input.reconciliationPath ?? 'evidence/reconciliation.json');
  const officialManifestPath = safeRelative(input.officialEvidenceManifestPath ?? 'evidence/official-evidence-manifest.json');
  const [sourceBefore, sourceAfter, reconciliation, officialManifest] = await Promise.all([
    readJsonInside(bundleRoot, sourceBeforePath), readJsonInside(bundleRoot, sourceAfterPath),
    readJsonInside(bundleRoot, reconciliationPath), readJsonInside(bundleRoot, officialManifestPath),
  ]);
  const stable = assertStableSnapshots(sourceBefore, sourceAfter, input);
  if (sourceBefore.betaEndedAt !== closure.betaEndedAt || sourceAfter.betaEndedAt !== closure.betaEndedAt ||
      reconciliation.sourceStable !== true || reconciliation.snapshotBoundaryId !== sourceBefore.snapshotBoundaryId ||
      reconciliation.databaseTotalsSha256 !== stable.databaseTotalsSha256 ||
      reconciliation.sourceBuildSha256 !== stable.sourceBuildSha256 ||
      canonical(reconciliation.operationBindings) !== canonical(stable.operationBindings)) fail('reconciliation_evidence_mismatch');
  if (!officialManifest || officialManifest.schemaVersion !== 'beta-official-evidence-source/v1' ||
      typeof officialManifest.sourceProfile !== 'string' || !officialManifest.sourceProfile ||
      !Array.isArray(officialManifest.runIds) || officialManifest.runIds.length < 1 ||
      !HASH.test(officialManifest.sourceBuildSha256 ?? '') || officialManifest.sourceBuildSha256 !== stable.sourceBuildSha256 ||
      !Array.isArray(officialManifest.files) || officialManifest.files.length < 1) fail('official_evidence_manifest_invalid');

  const expectedPaths = new Set([sourceBeforePath, sourceAfterPath, reconciliationPath, officialManifestPath]);
  const evidenceEntries = [];
  for (const row of officialManifest.files) {
    if (!row || typeof row.path !== 'string' || !row.path.startsWith('evidence/official/') ||
        !Number.isSafeInteger(row.bytes) || row.bytes < 0 || !HASH.test(row.sha256 ?? '') ||
        typeof row.role !== 'string' || !/^[a-z][a-z0-9_-]{1,63}$/.test(row.role)) fail('official_evidence_file_invalid');
    const path = safeRelative(row.path);
    const inspected = await inspectBackupFile(bundleRoot, path, 'evidence');
    if (inspected.bytes !== row.bytes || inspected.sha256 !== row.sha256) fail('official_evidence_file_mismatch');
    expectedPaths.add(path);
    evidenceEntries.push(inspected);
  }
  if (new Set(evidenceEntries.map((row) => row.path)).size !== evidenceEntries.length) fail('official_evidence_duplicate_path');

  const screenshots = [];
  for (const image of stable.imageFiles) {
    if (!image || typeof image.path !== 'string' || !image.path.startsWith('private-data/reports/images/') ||
        !Number.isSafeInteger(image.bytes) || image.bytes < 1 || !HASH.test(image.sha256 ?? '')) fail('source_image_reference_invalid');
    const path = safeRelative(image.path);
    const inspected = await inspectBackupFile(bundleRoot, path, 'screenshot');
    if (inspected.bytes !== image.bytes || inspected.sha256 !== image.sha256) fail('source_image_file_mismatch');
    expectedPaths.add(path);
    screenshots.push(inspected);
  }
  if (new Set(screenshots.map((row) => row.path)).size !== screenshots.length) fail('source_image_duplicate_path');

  const dumpPath = safeRelative(input.encryptedDatabasePath ?? 'database.dump.enc');
  if (dumpPath !== 'database.dump.enc') fail('database_dump_path_invalid');
  const databaseFilePath = resolve(bundleRoot, dumpPath);
  const databaseFile = await inspectBackupFile(bundleRoot, dumpPath, 'database');
  const dumpHandle = await open(databaseFilePath, 'r');
  try {
    const prefix = Buffer.alloc(ENCRYPTED_DUMP_HEADER.length);
    const { bytesRead } = await dumpHandle.read(prefix, 0, prefix.length, 0);
    if (bytesRead !== prefix.length || !prefix.equals(ENCRYPTED_DUMP_HEADER)) fail('database_dump_not_authenticated_encryption');
  } finally { await dumpHandle.close(); }
  expectedPaths.add(dumpPath);

  const actualPaths = await listRegularFiles(bundleRoot);
  if (canonical(actualPaths) !== canonical([...expectedPaths].sort())) fail('bundle_file_set_mismatch');
  const reconciliationEntry = await inspectBackupFile(bundleRoot, reconciliationPath, 'evidence');
  const sourceBeforeEntry = await inspectBackupFile(bundleRoot, sourceBeforePath, 'evidence');
  const sourceAfterEntry = await inspectBackupFile(bundleRoot, sourceAfterPath, 'evidence');
  const officialManifestEntry = await inspectBackupFile(bundleRoot, officialManifestPath, 'evidence');
  const inventory = {
    schemaVersion: 'beta-backup-inventory/v1', checkpointId: input.checkpointId, kind: input.kind,
    failureDomain: 'same_host', sourceBuildSha256: stable.sourceBuildSha256, capturedAt: input.capturedAt,
    betaEndedAt: closure.betaEndedAt, reconciliationEvidenceSha256: reconciliationEntry.sha256,
    databaseTotalsSha256: stable.databaseTotalsSha256, reportDeletionReceipts: stable.reportDeletionReceipts,
    files: [databaseFile, sourceBeforeEntry, sourceAfterEntry, reconciliationEntry, officialManifestEntry,
      ...evidenceEntries, ...screenshots],
    checkpointSource: {
      sourceDatabase: input.sourceDatabase, boundary: sourceBefore.snapshotBoundary,
      snapshotBoundaryId: sourceBefore.snapshotBoundaryId, sourceSnapshotAt: sourceBefore.snapshotAt,
      sourceAfterSnapshotAt: sourceAfter.snapshotAt, authoritativeClosureSha256: closureSha256,
      officialEvidenceSource: { manifestPath: officialManifestPath, manifestSha256: officialManifestEntry.sha256,
        sourceProfile: officialManifest.sourceProfile, runIds: officialManifest.runIds },
      operationBindings: stable.operationBindings,
      externalKeyRecovery: 'required_outside_bundle',
    },
  };
  validateBackupInventory(inventory);
  const inventoryPath = resolve(bundleRoot, 'inventory.json');
  if (!within(bundleRoot, inventoryPath)) fail('inventory_path_escape');
  const inventoryDigest = await writeJsonNew(inventoryPath, inventory);
  const fileVerification = await verifyBackupFiles(bundleRoot, inventory, {
    now: input.capturedAt, authoritativeBetaEndedAt: closure.betaEndedAt,
  });
  await writeJsonNew(resolve(bundleRoot, 'file-verification.json'), fileVerification);
  return { status: 'checkpoint_verified', checkpointId: input.checkpointId, inventory, inventorySha256: inventoryDigest.sha256,
    fileVerification, sourceStable: true, writesMayBeEnabled: false };
}

function safeIdList(value, label) {
  if (!Array.isArray(value) || value.some((id) => typeof id !== 'string' || !UUID.test(id)) ||
      new Set(value).size !== value.length) fail(`${label}_invalid`);
  return [...value].sort();
}
function safeOperationIds(value, label) {
  if (!Array.isArray(value) || value.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9_-]{12,128}$/.test(id)) ||
      new Set(value).size !== value.length) fail(`${label}_invalid`);
  return [...value].sort();
}

async function observeAbsoluteFile(path) {
  const inspectedPath = await inspectPathChain(path, 'file');
  const handle = await open(inspectedPath.canonicalPath, 'r');
  try {
    const before = await handle.stat();
    const hash = createHash('sha256');
    let bytes = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) { hash.update(chunk); bytes += chunk.length; }
    const after = await handle.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino || bytes !== after.size) fail('source_file_changed');
    return { bytes, sha256: hash.digest('hex'), canonicalPath: inspectedPath.canonicalPath };
  } finally { await handle.close(); }
}

async function copyPrivateImageSet({ privateDataDir, payloadRoot, imageFiles }) {
  const privateRoot = await assertNoSymlinkDirectory(privateDataDir);
  const expected = [];
  for (const image of imageFiles) {
    if (!image || typeof image.path !== 'string' || !image.path.startsWith('private-data/reports/images/') ||
        !Number.isSafeInteger(image.bytes) || image.bytes < 1 || !HASH.test(image.sha256 ?? '')) fail('source_image_invalid');
    const name = safeRelative(image.path).slice('private-data/reports/images/'.length);
    if (name.includes('/')) fail('source_image_path_invalid');
    const sourcePath = resolve(privateRoot, 'reports', 'images', name);
    const source = await observeAbsoluteFile(sourcePath);
    if (!within(privateRoot, source.canonicalPath) || source.bytes !== image.bytes || source.sha256 !== image.sha256) fail('source_image_mismatch');
    const copiedPath = resolve(payloadRoot, 'private-data', 'reports', 'images', name);
    await mkdir(parse(copiedPath).dir, { recursive: true, mode: 0o700 });
    await copyFile(source.canonicalPath, copiedPath, 1);
    const copied = await inspectBackupFile(payloadRoot, `private-data/reports/images/${name}`, 'screenshot');
    if (copied.bytes !== image.bytes || copied.sha256 !== image.sha256) fail('source_image_copy_mismatch');
    expected.push(image.path);
  }
  const actual = await listRegularFiles(privateRoot, 'reports/images').catch((error) => {
    if (String(error?.message ?? '').includes('ENOENT') || String(error?.message ?? '').includes('required_path_missing')) return [];
    throw error;
  });
  const actualPaths = actual.map((path) => `private-data/${path}`);
  if (canonical(actualPaths) !== canonical([...expected].sort())) fail('source_image_set_changed');
  return [...expected].sort();
}

async function copyOfficialEvidence({ sourceRoot, payloadRoot, officialEvidence, expectedSourceBuildSha256 }) {
  if (!officialEvidence || typeof officialEvidence.sourceProfile !== 'string' || !officialEvidence.sourceProfile ||
      !Array.isArray(officialEvidence.runIds) || officialEvidence.runIds.length < 1 ||
      !Array.isArray(officialEvidence.files) || officialEvidence.files.length < 1) fail('official_evidence_missing');
  const sourceBase = await inspectPathChain(sourceRoot, 'directory').then((row) => row.canonicalPath);
  const rows = [];
  const sourceRows = [];
  const manifestFiles = [];
  const targetPaths = new Set();
  for (const file of officialEvidence.files) {
    const relativePath = safeRelative(file.relativePath);
    if (targetPaths.has(relativePath.toLowerCase())) fail('official_evidence_duplicate_path');
    targetPaths.add(relativePath.toLowerCase());
    const sourcePath = resolve(sourceBase, safeRelative(file.sourcePath));
    const source = await observeAbsoluteFile(sourcePath);
    if (!within(sourceBase, source.canonicalPath) || !file.role || !/^[a-z][a-z0-9_-]{1,63}$/.test(file.role)) fail('official_evidence_path_invalid');
    const targetRelative = `evidence/official/${relativePath}`;
    const targetPath = resolve(payloadRoot, ...targetRelative.split('/'));
    await mkdir(parse(targetPath).dir, { recursive: true, mode: 0o700 });
    await copyFile(source.canonicalPath, targetPath, 1);
    const observed = await inspectBackupFile(payloadRoot, targetRelative, 'evidence');
    if (observed.bytes !== source.bytes || observed.sha256 !== source.sha256) fail('official_evidence_copy_mismatch');
    rows.push(observed);
    sourceRows.push({ path: source.canonicalPath, bytes: source.bytes, sha256: source.sha256 });
    manifestFiles.push({ path: targetRelative, bytes: observed.bytes, sha256: observed.sha256, role: file.role });
  }
  const manifest = { schemaVersion: 'beta-official-evidence-source/v1', sourceProfile: officialEvidence.sourceProfile,
    runIds: safeIdList(officialEvidence.runIds, 'official_run_ids'), sourceBuildSha256: officialEvidence.sourceBuildSha256,
    files: manifestFiles };
  if (!HASH.test(manifest.sourceBuildSha256 ?? '') || manifest.sourceBuildSha256 !== expectedSourceBuildSha256) fail('official_source_build_missing');
  const manifestPath = resolve(payloadRoot, 'evidence/official-evidence-manifest.json');
  await mkdir(parse(manifestPath).dir, { recursive: true, mode: 0o700 });
  await writeJsonNew(manifestPath, manifest);
  const manifestDigest = await inspectBackupFile(payloadRoot, 'evidence/official-evidence-manifest.json', 'evidence');
  return { manifest, files: rows, sourceFiles: sourceRows, manifestDigest };
}

async function writeDumpStream(stream, path) {
  if (!stream || typeof stream.pipe !== 'function' && typeof stream[Symbol.asyncIterator] !== 'function') fail('database_dump_stream_invalid');
  const output = createWriteStream(path, { flags: 'wx', mode: 0o600 });
  try { await pipeline(stream, output); }
  catch { fail('database_dump_failed'); }
  const inspected = await inspectBackupFile(parse(path).dir, parse(path).base, 'database');
  if (inspected.bytes < 1) fail('database_dump_empty');
  return inspected;
}

function validateCombinedSnapshot(snapshot, databaseName, boundaryId) {
  const observer = snapshot?.observerIdentity;
  if (!snapshot || snapshot.schemaVersion !== 'beta-combined-source-observation/v1' ||
      snapshot.sourceDatabase !== databaseName || snapshot.snapshotBoundary !== 'admission_frozen_database_quiescent' ||
      snapshot.snapshotBoundaryId !== boundaryId || !validIso(snapshot.snapshotAt) ||
      !HASH.test(snapshot.sourceBuildSha256 ?? '') || !HASH.test(snapshot.databaseTotalsSha256 ?? '') ||
      !observer || observer.databaseRole !== 'oid_observer' || observer.databaseName !== databaseName || observer.transactionReadOnly !== 'on' ||
      !snapshot.tableFingerprints || typeof snapshot.tableFingerprints !== 'object' || Array.isArray(snapshot.tableFingerprints)) fail('source_observation_invalid');
  assertOperationBindings(snapshot.operationBindings);
  if (!Array.isArray(snapshot.imageFiles) || !Array.isArray(snapshot.reportDeletionReceipts) ||
      !Number.isSafeInteger(snapshot.reportCount) || snapshot.reportCount < 0 ||
      !Number.isSafeInteger(snapshot.uploadCount) || snapshot.uploadCount < 0) fail('source_observation_support_state_invalid');
  const ids = snapshot.originalIds;
  if (!ids || typeof ids !== 'object') fail('source_operation_ids_missing');
  return {
    completedRunIds: safeIdList(ids.completedRunIds, 'completed_run_ids'),
    queuedInterruptedUnknownRunIds: safeIdList(ids.queuedInterruptedUnknownRunIds, 'pending_run_ids'),
    operationIds: safeOperationIds(ids.operationIds, 'operation_ids'),
    bonusGrantOperationIds: safeOperationIds(ids.bonusGrantOperationIds, 'bonus_operation_ids'),
    reportOperationIds: safeOperationIds(ids.reportOperationIds, 'report_operation_ids'),
  };
}

/**
 * Capture a real combined checkpoint while admission is frozen and PostgreSQL is quiescent.
 * The only plaintext staging area is mode 0700 and is removed before returning; the published bundle is AES-GCM sealed.
 */
export async function createCombinedCheckpoint({ source, checkpoint, adapters, keyRecovery, now = new Date().toISOString() }) {
  if (!source || typeof source.databaseName !== 'string' || !/^[A-Za-z0-9_]{1,63}$/.test(source.databaseName) ||
      !isAbsolute(source.privateDataDir ?? '') || !isAbsolute(source.closureStatePath ?? '') ||
      !isAbsolute(source.officialEvidenceRoot ?? '') || !HASH.test(source.sourceBuildSha256 ?? '') ||
      !checkpoint || !isAbsolute(checkpoint.bundleRoot ?? '') || !isAbsolute(checkpoint.externalKeyRecoveryPath ?? '') ||
      !['daily', 'pre_migration', 'retention_sanitized'].includes(checkpoint.kind) || !adapters || !keyRecovery ||
      typeof keyRecovery.protectMaterial !== 'function') fail('combined_input_invalid');
  for (const name of ['acquireAdmissionFreeze', 'releaseAdmissionFreeze', 'assertQuiescent', 'observeReadOnly',
    'streamDatabaseDump', 'readOfficialEvidence']) if (typeof adapters[name] !== 'function') fail(`adapter_${name}_missing`);
  if (!validIso(now)) fail('captured_time_invalid');
  const bundleRoot = await assertNoSymlinkDirectory(checkpoint.bundleRoot);
  const keyPath = resolve(checkpoint.externalKeyRecoveryPath);
  if (within(bundleRoot, keyPath) || within(keyPath, bundleRoot)) fail('external_key_path_invalid');
  const checkpointId = checkpoint.checkpointId ?? randomUUID();
  if (!UUID.test(checkpointId)) fail('checkpoint_id_invalid');
  const entries = await readdir(bundleRoot);
  if (entries.length) fail('checkpoint_staging_not_empty');
  const workRoot = resolve(bundleRoot, `.plaintext-${randomUUID().replaceAll('-', '')}`);
  const payloadRoot = resolve(workRoot, 'payload');
  await mkdir(workRoot, { recursive: false, mode: 0o700 });
  await mkdir(payloadRoot, { recursive: false, mode: 0o700 });
  let lease;
  let sealed = false;
  try {
    lease = await adapters.acquireAdmissionFreeze({ databaseName: source.databaseName, checkpointId });
    if (!lease || lease.status !== 'frozen' || lease.admissionFrozen !== true || typeof lease.leaseId !== 'string' ||
        lease.leaseId.length < 16 || typeof lease.boundaryId !== 'string' || lease.boundaryId.length < 16) fail('admission_freeze_not_acquired');
    await adapters.assertQuiescent({ databaseName: source.databaseName, boundaryId: lease.boundaryId, checkpointId });
    const before = await adapters.observeReadOnly({ databaseName: source.databaseName, boundaryId: lease.boundaryId, checkpointId });
    const originalIds = validateCombinedSnapshot(before, source.databaseName, lease.boundaryId);
    const closureBytesBefore = await readFile(source.closureStatePath);
    let closure;
    try { closure = JSON.parse(closureBytesBefore.toString('utf8')); } catch { fail('authoritative_closure_invalid'); }
    validateClosure(closure);
    const privateImagePaths = await copyPrivateImageSet({ privateDataDir: source.privateDataDir, payloadRoot, imageFiles: before.imageFiles });
    const officialEvidence = await adapters.readOfficialEvidence({ databaseName: source.databaseName, snapshot: before, checkpointId });
    const officialRoot = await copyOfficialEvidence({ sourceRoot: source.officialEvidenceRoot, payloadRoot, officialEvidence,
      expectedSourceBuildSha256: source.sourceBuildSha256 });
    if (officialRoot.manifest.sourceBuildSha256 !== source.sourceBuildSha256) fail('official_source_build_mismatch');
    const closureCopyPath = resolve(payloadRoot, 'operator/authoritative-closure.json');
    await mkdir(parse(closureCopyPath).dir, { recursive: true, mode: 0o700 });
    await writeJsonNew(closureCopyPath, closure);
    const dumpStream = await adapters.streamDatabaseDump({ databaseName: source.databaseName, boundaryId: lease.boundaryId, checkpointId });
    const dumpPath = resolve(payloadRoot, 'database.dump');
    const databaseDump = await writeDumpStream(dumpStream, dumpPath);
    const after = await adapters.observeReadOnly({ databaseName: source.databaseName, boundaryId: lease.boundaryId, checkpointId });
    validateCombinedSnapshot(after, source.databaseName, lease.boundaryId);
    const stable = assertStableSnapshots(before, after, { sourceDatabase: source.databaseName,
      sourceBuildSha256: source.sourceBuildSha256, capturedAt: before.snapshotAt });
    if (after.sourceBuildSha256 !== source.sourceBuildSha256 || closureBytesBefore.compare(await readFile(source.closureStatePath)) !== 0) fail('source_or_closure_changed_during_checkpoint');
    for (const row of officialRoot.sourceFiles) {
      const afterCopy = await observeAbsoluteFile(row.path);
      if (afterCopy.bytes !== row.bytes || afterCopy.sha256 !== row.sha256) fail('official_evidence_changed_during_checkpoint');
    }
    const sourceBefore = { ...before, originalIds };
    const sourceAfter = { ...after, originalIds: validateCombinedSnapshot(after, source.databaseName, lease.boundaryId) };
    const reconciliation = {
      schemaVersion: 'beta-combined-checkpoint-reconciliation/v1', sourceStable: true,
      snapshotBoundaryId: lease.boundaryId, databaseTotalsSha256: stable.databaseTotalsSha256,
      sourceBuildSha256: stable.sourceBuildSha256, operationBindings: stable.operationBindings,
      databaseDumpSha256: databaseDump.sha256, imageFilePaths: privateImagePaths,
      officialEvidenceManifestSha256: officialRoot.manifestDigest.sha256,
      authoritativeClosureSha256: sha256(closureBytesBefore),
    };
    for (const [name, value] of [['source-before.json', sourceBefore], ['source-after.json', sourceAfter],
      ['reconciliation.json', reconciliation]]) {
      const path = resolve(payloadRoot, 'evidence', name);
      await mkdir(parse(path).dir, { recursive: true, mode: 0o700 });
      await writeJsonNew(path, value);
    }
    const closureTime = closure.betaEndedAt;
    const sealedResult = await sealCheckpointPayload({ payloadRoot, bundleRoot,
      encryptedPath: resolve(bundleRoot, 'checkpoint.bundle.enc'), checkpointId,
      externalKeyRecoveryPath: keyPath,
      protectKey: async ({ checkpointId: id, key }) => {
        const runtimeSecrets = typeof adapters.getRuntimeRecoverySecrets === 'function'
          ? await adapters.getRuntimeRecoverySecrets({ checkpointId: id }) : null;
        const secretKeys = ['authSecret', 'bonusCodeVerifierSecret', 'googleClientId', 'googleClientSecret'];
        if (!runtimeSecrets || typeof runtimeSecrets !== 'object' || Array.isArray(runtimeSecrets) ||
            secretKeys.some((name) => typeof runtimeSecrets[name] !== 'string' || runtimeSecrets[name].length < 16)) {
          fail('runtime_recovery_secrets_missing');
        }
        return keyRecovery.protectMaterial({ checkpointId: id, bundleKey: key, runtimeSecrets });
      } });
    sealed = true;
    const artifact = sealedResult.artifact;
    const evidenceRow = await inspectBackupFile(payloadRoot, 'evidence/reconciliation.json', 'evidence');
    const inventory = {
      schemaVersion: CHECKPOINT_SCHEMA_V2, checkpointId, kind: checkpoint.kind, failureDomain: 'same_host',
      sourceBuildSha256: stable.sourceBuildSha256, capturedAt: before.snapshotAt, betaEndedAt: closureTime,
      reconciliationEvidenceSha256: evidenceRow.sha256, databaseTotalsSha256: stable.databaseTotalsSha256,
      reportDeletionReceipts: stable.reportDeletionReceipts,
      payloadManifestSha256: sealedResult.payloadManifest.payloadManifestSha256,
      recoveryEnvelopeSha256: sealedResult.keyRecovery.envelopeSha256,
      payloadSummary: { reportCount: before.reportCount, uploadCount: before.uploadCount,
        screenshotCount: before.imageFiles.length, screenshotBytes: before.imageFiles.reduce((sum, row) => sum + row.bytes, 0),
        officialEvidenceFileCount: officialRoot.files.length, databaseDumpBytes: databaseDump.bytes },
      operationBindings: stable.operationBindings, files: [artifact],
      checkpointSource: { sourceDatabase: source.databaseName, boundary: 'admission_frozen_database_quiescent',
        snapshotBoundaryId: lease.boundaryId, sourceSnapshotAt: before.snapshotAt, sourceAfterSnapshotAt: after.snapshotAt,
        officialEvidenceSource: { profile: officialRoot.manifest.sourceProfile, runIdCount: officialRoot.manifest.runIds.length,
          runIdsSha256: sha256(Buffer.from(canonical(officialRoot.manifest.runIds))) },
        operationBindings: stable.operationBindings, externalKeyRecovery: 'required_outside_bundle' },
    };
    validateBackupInventory(inventory);
    const inventoryDigest = await writeJsonNew(resolve(bundleRoot, 'inventory.json'), inventory);
    const observedBundle = await inspectBackupFile(bundleRoot, artifact.path, 'sealed_bundle');
    if (observedBundle.sha256 !== artifact.sha256 || observedBundle.bytes !== artifact.bytes) fail('sealed_bundle_changed');
    return { status: 'checkpoint_verified', checkpointId, bundleRoot, inventoryPath: resolve(bundleRoot, 'inventory.json'),
      inventory, inventorySha256: inventoryDigest.sha256, operationBindings: stable.operationBindings,
      originalIds, source: { before, after }, payloadSummary: inventory.payloadSummary,
      writesMayBeEnabled: false };
  } catch (error) {
    if (sealed) await rm(keyPath, { force: true }).catch(() => undefined);
    await rm(resolve(bundleRoot, 'checkpoint.bundle.enc'), { force: true }).catch(() => undefined);
    await rm(resolve(bundleRoot, 'inventory.json'), { force: true }).catch(() => undefined);
    throw error;
  } finally {
    await rm(workRoot, { recursive: true, force: true }).catch(() => undefined);
    if (lease) await adapters.releaseAdmissionFreeze({ databaseName: source.databaseName,
      boundaryId: lease.boundaryId, checkpointId, leaseId: lease.leaseId });
  }
}
