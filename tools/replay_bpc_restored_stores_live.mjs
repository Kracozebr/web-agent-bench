import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from 'node:path';

const HASH = /^[a-f0-9]{64}$/;
const ACCEPTANCE_DB = /^oid_acceptance_[a-f0-9]{32}$/;
const RESTORE_DB = /^oid_restore_[a-f0-9]{32}$/;
const MAX_DIFFERING_TABLES = 64;
const STORAGE_KEY = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OFFICIAL_EVIDENCE_SEALED_PREFIX = 'evidence/official/';
const OFFICIAL_EVIDENCE_CLONE_PREFIX = 'official-evidence/';
const OFFICIAL_EVIDENCE_SOURCE_MANIFEST_PATH = 'evidence/official-evidence-manifest.json';
const OFFICIAL_EVIDENCE_MANIFEST_PATH = 'operator/official-evidence-manifest.json';
const OFFICIAL_EVIDENCE_RECEIPT_PATH = 'operator/official-evidence-restore.json';
const MAX_OFFICIAL_EVIDENCE_FILES = 8192;
const MAX_OFFICIAL_EVIDENCE_ENTRIES = 16384;
const REPORT_TABLES = new Set([
  'oid_support_report',
  'oid_support_report_audit',
  'oid_support_image_upload',
  'oid_support_image_chunk',
  'oid_support_report_deletion_receipt',
  'oid_support_upload_gc_receipt',
  'oid_support_image_input_usage',
  'oid_support_report_retention_state',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function assert(condition, code) {
  if (!condition) fail(code);
}

function parseArgs(args) {
  assert(args.length >= 5, 'capture_and_private_roots_required');
  const capturePath = args[0];
  const options = new Map();
  for (let index = 1; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    assert((option === '--source-private-dir' || option === '--restore-private-base') &&
      typeof value === 'string' && value.length > 0 && !options.has(option),
    'command_line_option_invalid');
    assert(isAbsolute(value), 'private_root_must_be_absolute');
    options.set(option, value);
  }
  assert(options.size === 2, 'private_root_arguments_missing');
  return { capturePath, sourcePrivateDir: options.get('--source-private-dir'),
    restorePrivateBase: options.get('--restore-private-base') };
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) =>
      JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

function groupHash(tableFingerprints, predicate) {
  const selected = Object.fromEntries(Object.entries(tableFingerprints).filter(([name]) => predicate(name)));
  return sha256(Buffer.from(canonical(selected)));
}

function isFinancialTable(name) {
  return name.startsWith('oid_ledger_') || name.startsWith('oid_bonus_') ||
    name === 'oid_run_reservation' || name === 'oid_run_budget_hold';
}

function isBenchmarkTable(name) {
  return name === 'oid_benchmark_run' || name.startsWith('oid_run_') ||
    name.startsWith('oid_task_') || name.startsWith('oid_ranked_');
}

function isBusinessTable(name) {
  return isFinancialTable(name) || isBenchmarkTable(name) || REPORT_TABLES.has(name);
}

function quoteIdentifier(value) {
  return '"' + String(value).replaceAll('"', '""') + '"';
}

function isWithin(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + sep));
}

async function findRepoRoot(capturePath) {
  let current = dirname(capturePath);
  for (let depth = 0; depth < 12; depth += 1) {
    try {
      await lstat(resolve(current, 'packages', 'owner-acceptance', 'package.json'));
      return await realpath(current);
    } catch { /* keep walking toward filesystem root */ }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  fail('repository_root_not_found');
}

async function resolveRepoFile(repoRoot, relativePath) {
  assert(typeof relativePath === 'string' && relativePath.length > 0 &&
    !relativePath.includes('\\') && !relativePath.startsWith('/') &&
    !relativePath.split('/').some((part) => !part || part === '.' || part === '..'),
  'artifact_reference_path_invalid');
  const target = resolve(repoRoot, ...relativePath.split('/'));
  assert(isWithin(repoRoot, target), 'artifact_reference_path_outside_repository');
  const relParts = relative(repoRoot, target).split(sep).filter(Boolean);
  let cursor = repoRoot;
  for (let index = 0; index < relParts.length; index += 1) {
    cursor = resolve(cursor, relParts[index]);
    const info = await lstat(cursor);
    assert(!info.isSymbolicLink(), 'artifact_reference_symlink_rejected');
    if (index < relParts.length - 1) assert(info.isDirectory(), 'artifact_reference_parent_invalid');
    else assert(info.isFile(), 'artifact_reference_not_file');
  }
  return target;
}

async function readCapture(captureArg) {
  assert(typeof captureArg === 'string' && captureArg.length > 0, 'capture_path_required');
  const capturePath = resolve(captureArg);
  const captureInfo = await lstat(capturePath);
  assert(captureInfo.isFile() && !captureInfo.isSymbolicLink() &&
    capturePath.toLowerCase().endsWith((sep + 'capture.json').toLowerCase()), 'capture_file_invalid');
  const repoRoot = await findRepoRoot(capturePath);
  const realCapturePath = await realpath(capturePath);
  assert(isWithin(repoRoot, realCapturePath), 'capture_outside_repository');
  const rawBytes = await readFile(realCapturePath);
  let document;
  try { document = JSON.parse(rawBytes.toString('utf8')); } catch { fail('capture_json_invalid'); }
  const result = document?.result?.schemaVersion === 'bpc-combined-restore-runtime-observation/v1'
    ? document.result
    : document?.schemaVersion === 'bpc-combined-restore-runtime-observation/v1' ? document : null;
  assert(result && result.status === 'verified' && result.scenarioId === 'BPC-SC-022',
    'combined_restore_result_missing');
  return { capturePath: realCapturePath, captureSha256: sha256(rawBytes), repoRoot, document, result };
}

function validateSnapshot(snapshot, databaseName, label) {
  assert(snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot), label + '_snapshot_missing');
  assert(snapshot.sourceDatabase === databaseName &&
    snapshot.observerIdentity?.databaseName === databaseName &&
    snapshot.observerIdentity?.databaseRole === 'oid_observer' &&
    snapshot.observerIdentity?.transactionReadOnly === 'on',
  label + '_artifact_observer_binding_invalid');
  assert(snapshot.tableFingerprints && typeof snapshot.tableFingerprints === 'object' &&
    !Array.isArray(snapshot.tableFingerprints) && Object.keys(snapshot.tableFingerprints).length > 0,
  label + '_artifact_table_fingerprints_missing');
  assert(HASH.test(snapshot.sequenceSha256 ?? '') && HASH.test(snapshot.databaseTotalsSha256 ?? '') &&
    HASH.test(snapshot.financialStateSha256 ?? '') && HASH.test(snapshot.benchmarkStateSha256 ?? '') &&
    HASH.test(snapshot.reportStateSha256 ?? ''),
  label + '_artifact_hashes_invalid');
}

function validateActualDatabaseNames(sourceDb, normalDb, expiredDb) {
  assert(ACCEPTANCE_DB.test(sourceDb ?? '') && RESTORE_DB.test(normalDb ?? '') &&
    RESTORE_DB.test(expiredDb ?? '') && new Set([sourceDb, normalDb, expiredDb]).size === 3,
  'database_names_invalid_or_not_isolated');
}

function withDatabase(observerUrl, databaseName) {
  const url = new URL(observerUrl);
  url.pathname = '/' + databaseName;
  return url.href;
}

async function connectPg(repoRoot) {
  const require = createRequire(resolve(repoRoot, 'packages', 'owner-acceptance', 'package.json'));
  let Pool;
  try { ({ Pool } = require('pg')); } catch { fail('pinned_pg_driver_missing'); }
  return Pool;
}

async function checkedDirectoryRoot(value, label) {
  assert(typeof value === 'string' && isAbsolute(value), label + '_root_must_be_absolute');
  const absolute = resolve(value);
  let current = parse(absolute).root;
  const parts = relative(current, absolute).split(sep).filter(Boolean);
  assert(parts.length > 0, label + '_root_invalid');
  for (let index = 0; index < parts.length; index += 1) {
    current = resolve(current, parts[index]);
    let info;
    try { info = await lstat(current); } catch { fail(label + '_root_missing'); }
    assert(!info.isSymbolicLink(), label + '_root_symlink_rejected');
    assert(info.isDirectory(), label + '_root_not_directory');
  }
  const physical = await realpath(absolute);
  assert(resolve(physical).toLowerCase() === absolute.toLowerCase(), label + '_root_realpath_mismatch');
  return physical;
}

async function privateDataRoots(sourcePrivateDir, restorePrivateBase, sourceDatabase, normalDatabase, expiredDatabase) {
  assert(basename(sourcePrivateDir) === 'private-data' &&
    basename(dirname(sourcePrivateDir)) === sourceDatabase,
  'source_private_root_not_bound_to_source_database');
  assert(basename(restorePrivateBase) === 'beta-restores', 'restore_private_base_name_invalid');
  const source = await checkedDirectoryRoot(sourcePrivateDir, 'source_private');
  const restoreBase = await checkedDirectoryRoot(restorePrivateBase, 'restore_private');
  const normal = await checkedDirectoryRoot(resolve(restoreBase, normalDatabase, 'private-data'), 'normal_private');
  const expired = await checkedDirectoryRoot(resolve(restoreBase, expiredDatabase, 'private-data'), 'expired_private');
  return { source, normal, expired };
}

function officialReferenceRows(sourceReferences, label) {
  assert(Array.isArray(sourceReferences) && sourceReferences.length > 0,
    label + '_source_references_missing');
  const rows = sourceReferences.map((row) => {
    assert(row && typeof row.path === 'string' && row.path.length > 0 &&
      !row.path.includes('\\') && !row.path.startsWith('/') && !row.path.includes(':') &&
      !row.path.split('/').some((part) => !part || part === '.' || part === '..') &&
      typeof row.role === 'string' && /^[a-z][a-z0-9_-]{1,63}$/.test(row.role) &&
      Number.isSafeInteger(row.bytes) && row.bytes > 0 && HASH.test(row.sha256 ?? ''),
    label + '_source_reference_invalid');
    return { relativePath: row.path, role: row.role, bytes: row.bytes, sha256: row.sha256 };
  }).sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const unique = new Set(rows.map((row) => row.relativePath.toLowerCase()));
  assert(unique.size === rows.length, label + '_source_reference_duplicate');
  return rows;
}

function restoredOfficialReferenceRows(restore, label) {
  assert(Array.isArray(restore?.verifiedOfficialEvidenceFiles) &&
    restore.verifiedOfficialEvidenceFiles.length > 0 &&
    restore.verifiedOfficialEvidenceFiles.length <= MAX_OFFICIAL_EVIDENCE_FILES,
  label + '_restored_inventory_missing');
  const rows = restore.verifiedOfficialEvidenceFiles.map((row) => {
    assert(row && typeof row.relativePath === 'string' && row.relativePath.length > 0 &&
      !row.relativePath.includes('\\') && !row.relativePath.startsWith('/') && !row.relativePath.includes(':') &&
      !row.relativePath.split('/').some((part) => !part || part === '.' || part === '..') &&
      row.path === OFFICIAL_EVIDENCE_CLONE_PREFIX + row.relativePath &&
      typeof row.role === 'string' && /^[a-z][a-z0-9_-]{1,63}$/.test(row.role) &&
      Number.isSafeInteger(row.bytes) && row.bytes > 0 && HASH.test(row.sha256 ?? ''),
    label + '_restored_inventory_row_invalid');
    return { path: row.path, relativePath: row.relativePath, role: row.role,
      bytes: row.bytes, sha256: row.sha256 };
  }).sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  assert(new Set(rows.map((row) => row.relativePath.toLowerCase())).size === rows.length,
    label + '_restored_inventory_duplicate');
  return rows;
}

async function listOfficialEvidenceTree(officialRoot, label) {
  const found = [];
  let visited = 0;
  const walk = async (directory, depth) => {
    assert(depth <= 16, label + '_tree_depth_exceeded');
    const entries = await readdir(directory, { withFileTypes: true });
    visited += entries.length;
    assert(visited <= MAX_OFFICIAL_EVIDENCE_ENTRIES, label + '_tree_entry_limit_exceeded');
    for (const entry of entries) {
      const absolute = resolve(directory, entry.name);
      const info = await lstat(absolute);
      assert(!info.isSymbolicLink(), label + '_tree_symlink_rejected');
      if (info.isDirectory()) await walk(absolute, depth + 1);
      else if (info.isFile()) {
        const relativePath = relative(officialRoot, absolute).split(sep).join('/');
        assert(relativePath && !relativePath.startsWith('../') && !relativePath.includes('\\'),
          label + '_tree_path_invalid');
        found.push(relativePath);
        assert(found.length <= MAX_OFFICIAL_EVIDENCE_FILES, label + '_tree_file_limit_exceeded');
      } else assert(false, label + '_tree_entry_type_invalid');
    }
  };
  await walk(officialRoot, 0);
  return found.sort((left, right) => left.localeCompare(right));
}

async function readContainedFile(root, relativePath, label) {
  const target = await resolveRepoFile(root, relativePath);
  const physical = await realpath(target);
  assert(isWithin(root, physical), label + '_path_outside_root');
  const bytes = await readFile(physical);
  return { target: physical, bytes };
}

async function verifyRestoredOfficialEvidence(restore, sourceReferences, checkpoint, restoreBase,
  restoreDatabase, repoRoot, label) {
  assert(restore && restore.restoreDatabaseName === restoreDatabase,
  label + '_restore_identity_missing');
  const expectedRoot = resolve(restoreBase, restoreDatabase);
  const cloneRoot = await checkedDirectoryRoot(expectedRoot, label + '_restore_root');
  const expectedOfficialRoot = resolve(cloneRoot, 'official-evidence');
  const officialRoot = await checkedDirectoryRoot(expectedOfficialRoot, label + '_official_root');
  assert(typeof restore.officialEvidenceRoot === 'string' && isAbsolute(restore.officialEvidenceRoot) &&
    resolve(restore.officialEvidenceRoot).toLowerCase() === officialRoot.toLowerCase(),
  label + '_official_root_binding_invalid');

  const expectedRows = officialReferenceRows(sourceReferences, label);
  const restoredRows = restoredOfficialReferenceRows(restore, label);
  const expectedComparable = expectedRows.map((row) => ({ ...row,
    path: OFFICIAL_EVIDENCE_CLONE_PREFIX + row.relativePath }));
  assert(canonical(restoredRows) === canonical(expectedComparable),
    label + '_inventory_differs_from_checkpoint');

  for (const row of expectedRows) {
    const sourcePath = await resolveRepoFile(repoRoot, row.relativePath);
    const sourceBytes = await readFile(sourcePath);
    assert(sourceBytes.length === row.bytes && sha256(sourceBytes) === row.sha256,
      label + '_source_file_bytes_or_hash_mismatch');
  }

  const actualPaths = await listOfficialEvidenceTree(officialRoot, label);
  const expectedPaths = expectedRows.map((row) => row.relativePath).sort((left, right) => left.localeCompare(right));
  assert(canonical(actualPaths) === canonical(expectedPaths), label + '_tree_inventory_differs');
  let totalBytes = 0;
  for (const row of expectedRows) {
    const { bytes } = await readContainedFile(officialRoot, row.relativePath, label + '_file');
    assert(bytes.length === row.bytes && sha256(bytes) === row.sha256,
      label + '_file_bytes_or_hash_mismatch');
    totalBytes += bytes.length;
    assert(Number.isSafeInteger(totalBytes), label + '_total_bytes_invalid');
  }

  const expectedManifestRows = expectedRows.map((row) => ({ path: OFFICIAL_EVIDENCE_SEALED_PREFIX +
    row.relativePath, bytes: row.bytes, sha256: row.sha256, role: row.role }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const { bytes: manifestBytes } = await readContainedFile(cloneRoot, OFFICIAL_EVIDENCE_MANIFEST_PATH,
    label + '_manifest');
  const manifestSha256 = checkpoint?.officialEvidenceManifestSha256;
  assert(HASH.test(manifestSha256 ?? '') && sha256(manifestBytes) === manifestSha256,
    label + '_manifest_bytes_or_hash_mismatch');
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch { fail(label + '_manifest_json_invalid'); }
  const manifestRows = Array.isArray(manifest?.files) ? [...manifest.files].sort((left, right) =>
    String(left?.path ?? '').localeCompare(String(right?.path ?? ''))) : null;
  assert(manifest?.schemaVersion === 'beta-official-evidence-source/v1' &&
    HASH.test(checkpoint?.sourceSnapshots?.afterRestore?.sourceBuildSha256 ?? '') &&
    manifest.sourceBuildSha256 === checkpoint.sourceSnapshots.afterRestore.sourceBuildSha256 &&
    canonical(manifestRows) === canonical(expectedManifestRows),
  label + '_manifest_inventory_binding_mismatch');

  const receiptRef = restore.officialEvidenceRestoreReceipt;
  assert(receiptRef && receiptRef.path === OFFICIAL_EVIDENCE_RECEIPT_PATH &&
    restore.officialEvidenceManifestPath === OFFICIAL_EVIDENCE_MANIFEST_PATH &&
    Number.isSafeInteger(receiptRef.bytes) && receiptRef.bytes > 0 && HASH.test(receiptRef.sha256 ?? ''),
  label + '_operator_receipt_reference_invalid');
  const { bytes: receiptBytes } = await readContainedFile(cloneRoot, receiptRef.path, label + '_receipt');
  assert(receiptBytes.length === receiptRef.bytes && sha256(receiptBytes) === receiptRef.sha256,
    label + '_operator_receipt_hash_mismatch');
  const receiptInfo = await lstat(resolve(cloneRoot, receiptRef.path));
  if (process.platform !== 'win32') assert((receiptInfo.mode & 0o077) === 0,
    label + '_operator_receipt_permissions_too_open');
  let receipt;
  try { receipt = JSON.parse(receiptBytes.toString('utf8')); }
  catch { fail(label + '_operator_receipt_json_invalid'); }
  const sourceBuildSha256 = checkpoint?.sourceSnapshots?.afterRestore?.sourceBuildSha256;
  const cloneManifestSha256 = restore.officialEvidenceManifestSha256 ??
    restore.checkpoint?.officialEvidenceManifestSha256;
  const cloneSourceBuildSha256 = restore.officialEvidenceSourceBuildSha256 ??
    restore.checkpoint?.sourceBuildSha256;
  assert(HASH.test(manifestSha256 ?? '') &&
    HASH.test(sourceBuildSha256 ?? '') &&
    receipt?.schemaVersion === 'beta-restored-official-evidence/v1' &&
    receipt.status === 'restored_verified' &&
    receipt.checkpointId === restore.checkpointId &&
    receipt.restoreDatabaseName === restoreDatabase &&
    receipt.sourceBuildSha256 === sourceBuildSha256 &&
    cloneSourceBuildSha256 === sourceBuildSha256 &&
    cloneManifestSha256 === manifestSha256 &&
    (restore.checkpoint?.sourceBuildSha256 === undefined || restore.checkpoint.sourceBuildSha256 === sourceBuildSha256) &&
    (restore.checkpoint?.officialEvidenceManifestSha256 === undefined || restore.checkpoint.officialEvidenceManifestSha256 === manifestSha256) &&
    receipt.manifestPath === OFFICIAL_EVIDENCE_MANIFEST_PATH &&
    receipt.sourceManifestPath === OFFICIAL_EVIDENCE_SOURCE_MANIFEST_PATH &&
    receipt.manifestSha256 === manifestSha256 &&
    receipt.fileCount === expectedRows.length && receipt.totalBytes === totalBytes &&
    Array.isArray(receipt.files) &&
    canonical(restoredOfficialReferenceRows({ verifiedOfficialEvidenceFiles: receipt.files }, label + '_receipt')) ===
      canonical(restoredRows),
  label + '_operator_receipt_binding_mismatch');
  return { verifiedFiles: expectedRows.length, totalBytes, receiptSha256: receiptRef.sha256,
    manifestSha256, exactCheckpointInventory: true, fileBytesAndHashesMatched: true };
}

async function verifyUploadFiles(privateDataDir, uploadRows, label) {
  assert(Array.isArray(uploadRows), label + '_image_upload_rows_missing');
  let verified = 0;
  const metadata = [];
  for (const row of uploadRows) {
    const bytesExpected = Number(row.output_bytes);
    assert(['ready', 'attached'].includes(row.status) && STORAGE_KEY.test(row.storage_key ?? '') &&
      Number.isSafeInteger(bytesExpected) && bytesExpected > 0 && HASH.test(row.output_sha256 ?? ''),
    label + '_image_upload_metadata_invalid');
    const components = ['reports', 'images', row.storage_key + '.webp'];
    let target = privateDataDir;
    for (let index = 0; index < components.length; index += 1) {
      target = resolve(target, components[index]);
      let info;
      try { info = await lstat(target); } catch { fail(label + '_image_file_missing'); }
      assert(!info.isSymbolicLink(), label + '_image_path_symlink_rejected');
      if (index < components.length - 1) assert(info.isDirectory(), label + '_image_parent_not_directory');
      else assert(info.isFile(), label + '_image_path_not_file');
    }
    const physical = await realpath(target);
    assert(isWithin(privateDataDir, physical), label + '_image_path_outside_private_root');
    const bytes = await readFile(physical);
    assert(bytes.length === bytesExpected && sha256(bytes) === row.output_sha256,
      label + '_image_file_hash_mismatch');
    metadata.push({ bytes: bytesExpected, sha256: row.output_sha256 });
    verified += 1;
  }
  metadata.sort((left, right) => left.sha256.localeCompare(right.sha256) || left.bytes - right.bytes);
  return { verifiedFiles: verified, metadata };
}

function compareImageMetadata(actualRows, expectedFiles, label) {
  assert(Array.isArray(expectedFiles), label + '_artifact_image_file_list_missing');
  const expected = expectedFiles.map((row) => ({ bytes: row.bytes, sha256: row.sha256 }))
    .sort((left, right) => left.sha256.localeCompare(right.sha256) || left.bytes - right.bytes);
  assert(canonical(actualRows) === canonical(expected), label + '_image_database_metadata_differs_from_capture');
}

async function assertExpiredImageDirectoryEmpty(privateDataDir) {
  const reportsDir = resolve(privateDataDir, 'reports');
  let reportsInfo;
  try { reportsInfo = await lstat(reportsDir); } catch (error) {
    if (error?.code === 'ENOENT') return { directoryPresent: false, directoriesChecked: 0, filesFound: 0 };
    fail('expired_reports_directory_inspection_failed');
  }
  assert(!reportsInfo.isSymbolicLink() && reportsInfo.isDirectory(), 'expired_reports_directory_unsafe');
  const imagesDir = resolve(reportsDir, 'images');
  let imageInfo;
  try { imageInfo = await lstat(imagesDir); } catch (error) {
    if (error?.code === 'ENOENT') return { directoryPresent: false, directoriesChecked: 0, filesFound: 0 };
    fail('expired_images_directory_inspection_failed');
  }
  assert(!imageInfo.isSymbolicLink() && imageInfo.isDirectory(), 'expired_images_directory_unsafe');
  const physicalImagesDir = await realpath(imagesDir);
  assert(isWithin(privateDataDir, physicalImagesDir), 'expired_images_directory_outside_private_root');
  let directoriesChecked = 0;
  let entriesChecked = 0;
  const visit = async (directory, depth) => {
    assert(depth <= 8, 'expired_image_directory_depth_exceeded');
    directoriesChecked += 1;
    const entries = await readdir(directory, { withFileTypes: true });
    entriesChecked += entries.length;
    assert(entriesChecked <= 4096, 'expired_image_directory_entry_limit_exceeded');
    for (const entry of entries) {
      const target = resolve(directory, entry.name);
      const info = await lstat(target);
      assert(!info.isSymbolicLink(), 'expired_image_tree_symlink_rejected');
      if (info.isDirectory()) await visit(target, depth + 1);
      else if (info.isFile()) fail('expired_private_image_files_remaining');
      else fail('expired_image_tree_entry_type_invalid');
    }
  };
  await visit(imagesDir, 0);
  return { directoryPresent: true, directoriesChecked, filesFound: 0 };
}

async function liveSnapshot(Pool, observerUrl, databaseName, label, reportId = null) {
  const pool = new Pool({ connectionString: withDatabase(observerUrl, databaseName), max: 1,
    connectionTimeoutMillis: 5_000, idleTimeoutMillis: 1_000, application_name: 'bpc-combined-live-verifier' });
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = (await client.query(
      "SELECT current_database() AS database_name,current_user AS database_role," +
      "current_setting('transaction_read_only') AS transaction_read_only"
    )).rows[0];
    assert(identity?.database_name === databaseName && identity.database_role === 'oid_observer' &&
      identity.transaction_read_only === 'on', label + '_observer_identity_or_readonly_invalid');

    const relationRows = (await client.query(
      'SELECT c.relname AS table_name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace ' +
      "WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname"
    )).rows;
    assert(relationRows.length > 0, label + '_public_table_inventory_empty');
    const tableFingerprints = {};
    for (const { table_name: tableName } of relationRows) {
      const rows = (await client.query(
        'SELECT to_jsonb(t)::text AS row_json FROM public.' + quoteIdentifier(tableName) + ' AS t'
      )).rows;
      const serializedRows = rows.map((row) => row.row_json).sort();
      const hash = createHash('sha256');
      for (const row of serializedRows) {
        hash.update(row);
        hash.update('\n');
      }
      tableFingerprints[tableName] = { rowCount: serializedRows.length, sha256: hash.digest('hex') };
    }
    const sequences = (await client.query(
      'SELECT schemaname,sequencename,last_value FROM pg_sequences ' +
      "WHERE schemaname='public' ORDER BY schemaname,sequencename"
    )).rows;
    const sequenceSha256 = sha256(Buffer.from(canonical(sequences)));
    const databaseTotalsSha256 = sha256(Buffer.from(canonical({ tableFingerprints, sequenceSha256 })));
    const reportCount = Number((await client.query('SELECT count(*)::text AS n FROM public.oid_support_report')).rows[0].n);
    const uploadCount = Number((await client.query('SELECT count(*)::text AS n FROM public.oid_support_image_upload')).rows[0].n);
    const rawChunkCount = Number((await client.query('SELECT count(*)::text AS n FROM public.oid_support_image_chunk')).rows[0].n);
    const deletionReceipts = (await client.query(
      'SELECT report_id::text,purge_status FROM public.oid_support_report_deletion_receipt ORDER BY report_id'
    )).rows.map((row) => ({ reportId: row.report_id, status: row.purge_status }))
      .sort((left, right) => left.reportId.localeCompare(right.reportId));
    const imageUploads = (await client.query(
      "SELECT id::text,report_id::text,status,storage_key::text,output_bytes::text,output_sha256 " +
      "FROM public.oid_support_image_upload WHERE status IN ('ready','attached') ORDER BY storage_key"
    )).rows;
    let reportBinding = null;
    if (reportId !== null) {
      assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reportId),
        label + '_report_id_invalid');
      const reports = (await client.query(
        'SELECT id::text,source,operation_id,payload_hash,run_id::text,task_id,action_id::text,status,revision ' +
        'FROM public.oid_support_report WHERE id=$1::uuid', [reportId]
      )).rows;
      const uploads = (await client.query(
        'SELECT id::text,report_id::text,status,output_bytes::text,output_sha256,output_mime,width,height ' +
        'FROM public.oid_support_image_upload WHERE report_id=$1::uuid ORDER BY id', [reportId]
      )).rows;
      reportBinding = { reports, uploads };
    }
    await client.query('COMMIT');
    return { databaseName, identity: {
      databaseName: identity.database_name, role: identity.database_role,
      transactionReadOnly: identity.transaction_read_only,
    }, tableFingerprints, sequenceSha256, databaseTotalsSha256, reportCount, uploadCount, rawChunkCount,
    deletionReceipts, reportBinding, imageUploads };
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => undefined);
    if (error?.code && /^[A-Za-z0-9_]+$/.test(error.code)) throw error;
    fail(label + '_readonly_snapshot_failed');
  } finally {
    client?.release();
    await pool.end();
  }
}

function compareTableMaps(actual, expected, label, exact) {
  assert(actual && expected && typeof actual === 'object' && typeof expected === 'object',
    label + '_table_fingerprints_missing');
  const actualNames = Object.keys(actual).sort();
  const expectedNames = Object.keys(expected).sort();
  assert(canonical(actualNames) === canonical(expectedNames), label + '_table_inventory_mismatch');
  const differences = [];
  for (const tableName of actualNames) {
    const left = actual[tableName];
    const right = expected[tableName];
    assert(left && right && Number.isSafeInteger(left.rowCount) && Number.isSafeInteger(right.rowCount) &&
      HASH.test(left.sha256 ?? '') && HASH.test(right.sha256 ?? ''), label + '_table_fingerprint_shape_invalid');
    if (left.rowCount !== right.rowCount || left.sha256 !== right.sha256) differences.push(tableName);
  }
  if (exact) assert(differences.length === 0, label + '_all_table_fingerprints_differ');
  else assert(differences.every((name) => !isBusinessTable(name)), label + '_business_table_fingerprint_differs');
  assert(differences.length <= MAX_DIFFERING_TABLES, label + '_operational_difference_list_unbounded');
  return differences;
}

function compareSource(actual, expected) {
  validateSnapshot(expected, actual.databaseName, 'source_checkpoint');
  const tableDifferences = compareTableMaps(actual.tableFingerprints, expected.tableFingerprints, 'source', true);
  assert(actual.sequenceSha256 === expected.sequenceSha256 &&
    actual.databaseTotalsSha256 === expected.databaseTotalsSha256,
  'source_sequence_or_total_hash_differs');
  return { databaseName: actual.databaseName, role: actual.identity.role,
    readonlyTransaction: actual.identity.transactionReadOnly, tableCount: Object.keys(actual.tableFingerprints).length,
    sequenceSha256: actual.sequenceSha256, databaseTotalsSha256: actual.databaseTotalsSha256,
    exactTableMatches: tableDifferences.length === 0 };
}

function compareClone(actual, expected, label) {
  validateSnapshot(expected, actual.databaseName, label + '_retry_snapshot');
  const tableDifferences = compareTableMaps(actual.tableFingerprints, expected.tableFingerprints, label, false);
  const groups = {
    financial: groupHash(actual.tableFingerprints, isFinancialTable) === expected.financialStateSha256,
    benchmark: groupHash(actual.tableFingerprints, isBenchmarkTable) === expected.benchmarkStateSha256,
    reports: groupHash(actual.tableFingerprints, (name) => REPORT_TABLES.has(name)) === expected.reportStateSha256,
  };
  assert(Object.values(groups).every(Boolean), label + '_business_group_hash_differs');
  return { databaseName: actual.databaseName, role: actual.identity.role,
    readonlyTransaction: actual.identity.transactionReadOnly, tableCount: Object.keys(actual.tableFingerprints).length,
    businessHashesMatch: groups, sequenceSha256: actual.sequenceSha256,
    sequenceHashMatchesRetrySnapshot: actual.sequenceSha256 === expected.sequenceSha256,
    boundedOperationalTableDifferences: tableDifferences };
}

async function verifyReportEvidence(repoRoot, result, sourceDatabase, reportRow, uploads) {
  const references = result.checkpoint?.verifiedOfficialEvidenceFiles;
  assert(Array.isArray(references), 'report_evidence_reference_list_missing');
  const matches = references.filter((row) => typeof row?.path === 'string' &&
    row.path.endsWith('/report-runtime.json') && HASH.test(row.sha256 ?? ''));
  assert(matches.length === 1, 'report_runtime_evidence_reference_ambiguous');
  const evidencePath = await resolveRepoFile(repoRoot, matches[0].path);
  const evidenceBytes = await readFile(evidencePath);
  assert(sha256(evidenceBytes) === matches[0].sha256, 'report_runtime_evidence_hash_mismatch');
  let evidence;
  try { evidence = JSON.parse(evidenceBytes.toString('utf8')); } catch { fail('report_runtime_evidence_json_invalid'); }
  const reportCase = result.reportCases;
  const receipt = evidence?.reportReceipt;
  assert(evidence?.schemaVersion === 'bpc-combined-report-evidence/v1' &&
    evidence.databaseName === sourceDatabase && receipt?.reportId === reportRow.id &&
    reportCase?.reportId === reportRow.id && reportCase.originalReportId === reportRow.id &&
    receipt.operationIdSha256 === sha256(Buffer.from(reportRow.operation_id)) &&
    receipt.operationIdSha256 === reportCase.reportOperationIdSha256 &&
    receipt.payloadSha256 === reportRow.payload_hash &&
    [200, 201].includes(receipt.responseStatus) &&
    evidence.runContext?.runId === reportRow.run_id && evidence.runContext?.taskId === reportRow.task_id &&
    evidence.runContext?.actionId === reportRow.action_id,
  'report_runtime_evidence_database_binding_mismatch');
  const expectedUploads = [...(reportCase.imageFilesVerified ?? [])].sort((a, b) => a.uploadId.localeCompare(b.uploadId));
  const actualUploads = [...uploads].sort((a, b) => a.id.localeCompare(b.id)).map((row) => ({
    uploadId: row.id, bytes: Number(row.output_bytes), sha256: row.output_sha256,
    mime: row.output_mime, width: row.width, height: row.height,
  }));
  assert(expectedUploads.length > 0 && canonical(actualUploads) === canonical(expectedUploads),
    'report_upload_database_metadata_mismatch');
  const uploadIdHashes = actualUploads.map((row) => sha256(Buffer.from(row.uploadId)));
  assert(Array.isArray(receipt.imageUploadIdsSha256) &&
    canonical([...receipt.imageUploadIdsSha256].sort()) === canonical([...uploadIdHashes].sort()),
  'report_upload_ids_evidence_mismatch');
  return { evidenceSha256: matches[0].sha256, reportReceiptMatched: true,
    uploadCount: actualUploads.length, uploadMetadataMatched: true,
    uploadIdsMatchedByHash: true };
}

function returnedImagePathReferences(value, found = []) {
  if (!value || typeof value !== 'object') return found;
  if (Array.isArray(value)) {
    for (const item of value) returnedImagePathReferences(item, found);
    return found;
  }
  if (typeof value.path === 'string' && /\.(webp|png|jpe?g|gif)$/i.test(value.path) &&
      Number.isSafeInteger(value.bytes) && value.bytes >= 0 && HASH.test(value.sha256 ?? '')) {
    found.push({ path: value.path, bytes: value.bytes, sha256: value.sha256 });
  }
  for (const child of Object.values(value)) returnedImagePathReferences(child, found);
  return found;
}

async function verifyReturnedImageFiles(repoRoot, document) {
  const refs = returnedImagePathReferences(document);
  let verified = 0;
  let inaccessible = 0;
  const allowedRoots = [repoRoot];
  const configuredCaptureRoot = process.env.OID_LOCAL_REPORT_CAPTURE_BASE;
  if (typeof configuredCaptureRoot === 'string' && configuredCaptureRoot.length > 0 &&
      isAbsolute(configuredCaptureRoot)) {
    try {
      const info = await lstat(configuredCaptureRoot);
      if (info.isDirectory() && !info.isSymbolicLink()) allowedRoots.push(await realpath(configuredCaptureRoot));
    } catch { /* an unavailable volume path is reported as inaccessible below */ }
  }
  for (const ref of refs) {
    let target;
    if (isAbsolute(ref.path)) {
      const absolutePath = resolve(ref.path);
      const allowedRoot = allowedRoots.find((root) => isWithin(root, absolutePath));
      if (!allowedRoot) {
        inaccessible += 1;
        continue;
      }
      const rel = relative(allowedRoot, absolutePath).split(sep).join('/');
      try { target = await resolveRepoFile(allowedRoot, rel); }
      catch (error) {
        if (error?.code === 'ENOENT') { inaccessible += 1; continue; }
        throw error;
      }
    } else {
      try { target = await resolveRepoFile(repoRoot, ref.path.split(sep).join('/')); }
      catch (error) {
        if (error?.code === 'ENOENT') { inaccessible += 1; continue; }
        throw error;
      }
    }
    const bytes = await readFile(target);
    assert(bytes.length === ref.bytes && sha256(bytes) === ref.sha256, 'returned_image_file_hash_mismatch');
    verified += 1;
  }
  return { returnedPaths: refs.length, fileContentsRechecked: verified, inaccessiblePaths: inaccessible };
}

async function verifyNormalReport(actual, result, document, repoRoot, sourceDatabase) {
  const reportCase = result.reportCases;
  assert(reportCase && typeof reportCase.reportId === 'string' && typeof reportCase.linkedRunId === 'string' &&
    typeof reportCase.linkedActionId === 'string', 'report_case_binding_missing');
  assert(actual.identity.role === 'oid_observer' && actual.identity.transactionReadOnly === 'on' &&
    Array.isArray(actual.reportBinding?.reports) && actual.reportBinding.reports.length === 1,
  'normal_report_readonly_snapshot_missing');
  const report = actual.reportBinding.reports[0];
  const uploads = actual.reportBinding.uploads;
  assert(report.id === reportCase.reportId && report.source === 'owner' &&
    report.run_id === reportCase.linkedRunId && report.task_id === 'S1' &&
    report.action_id === reportCase.linkedActionId && report.status === reportCase.sourceStatus &&
    report.revision === reportCase.sourceRevision,
  'normal_clone_report_binding_mismatch');
  assert(uploads.length > 0 && uploads.every((row) => row.status === 'attached' &&
    Number.isSafeInteger(Number(row.output_bytes)) && HASH.test(row.output_sha256 ?? '')),
  'normal_clone_report_upload_rows_invalid');
  const evidence = await verifyReportEvidence(repoRoot, result, sourceDatabase, report, uploads);
  const operationIdSha256 = sha256(Buffer.from(report.operation_id));
  assert(operationIdSha256 === reportCase.reportOperationIdSha256 &&
    operationIdSha256 === reportCase.originalReportOperationIdSha256,
  'normal_clone_report_operation_hash_mismatch');
  const imageFiles = await verifyReturnedImageFiles(repoRoot, document);
  return { reportBindingMatched: true, reportOperationIdSha256: operationIdSha256, payloadSha256: report.payload_hash,
    uploadCount: uploads.length, uploadMetadataMatched: evidence.uploadMetadataMatched,
    reportRuntimeEvidenceSha256: evidence.evidenceSha256,
    imageFileBytes: { databaseRowsMatchedCapture: true, ...imageFiles } };
}

async function verifyExpiredRetention(actual, expected, physicalImages) {
  assert(actual.reportCount === 0 && actual.uploadCount === 0 && actual.rawChunkCount === 0,
    'expired_clone_retained_report_upload_or_raw_chunk_rows');
  assert(Array.isArray(expected.imageFiles) && expected.imageFiles.length === 0 &&
    Number(expected.reportCount) === 0 && Number(expected.uploadCount) === 0,
  'expired_clone_artifact_claims_retained_images');
  const receipts = actual.deletionReceipts;
  assert(Array.isArray(receipts) && receipts.length > 0 && receipts.every((row) => row.status === 'complete') &&
    Array.isArray(expected.reportDeletionReceipts) &&
    canonical(receipts) === canonical(expected.reportDeletionReceipts),
  'expired_clone_deletion_receipts_missing_or_changed');
  const cloneSummary = expected;
  return { reportRows: actual.reportCount, uploadRows: actual.uploadCount, rawChunkRows: actual.rawChunkCount,
    deletionReceiptCount: receipts.length, allDeletionReceiptsComplete: true,
    receiptRowsMatchFinalRetrySnapshot: true,
    liveImageUploadFilesVerified: physicalImages.verifiedFiles,
    expiredImageDirectory: physicalImages.expiredDirectory,
    financialStatePreserved: groupHash(actual.tableFingerprints, isFinancialTable) === cloneSummary.financialStateSha256,
    benchmarkGradesPreserved: groupHash(actual.tableFingerprints, isBenchmarkTable) === cloneSummary.benchmarkStateSha256 };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { captureSha256, repoRoot, document, result } = await readCapture(args.capturePath);
  const sourceDatabase = result.sourceDatabase;
  const normalDatabase = result.restore?.restoreDatabaseName;
  const expiredDatabase = result.retentionExpiry?.cloneRestore?.restoreDatabaseName;
  validateActualDatabaseNames(sourceDatabase, normalDatabase, expiredDatabase);
  const privateRoots = await privateDataRoots(args.sourcePrivateDir, args.restorePrivateBase,
    sourceDatabase, normalDatabase, expiredDatabase);
  const officialReferences = result.checkpoint?.verifiedOfficialEvidenceFiles;
  const officialManifestSha256 = result.checkpoint?.officialEvidenceManifestSha256;
  assert(HASH.test(officialManifestSha256 ?? ''), 'checkpoint_official_manifest_sha256_missing');
  const normalOfficialEvidence = await verifyRestoredOfficialEvidence(result.restore, officialReferences,
    result.checkpoint, args.restorePrivateBase, normalDatabase, repoRoot, 'normal_clone_official_evidence');
  const expiredOfficialEvidence = await verifyRestoredOfficialEvidence(result.retentionExpiry?.cloneRestore,
    officialReferences, result.checkpoint, args.restorePrivateBase, expiredDatabase, repoRoot, 'expired_clone_official_evidence');
  const expectedSource = result.checkpoint?.sourceSnapshots?.afterRestore;
  const expectedNormal = result.retries?.snapshots?.after;
  const expectedExpired = result.retentionExpiry?.safeRetry?.snapshots?.after;
  validateSnapshot(expectedSource, sourceDatabase, 'source_checkpoint');
  validateSnapshot(expectedNormal, normalDatabase, 'normal_clone_retry');
  validateSnapshot(expectedExpired, expiredDatabase, 'expired_clone_retry');
  assert(typeof process.env.OID_OBSERVER_DATABASE_URL === 'string' &&
    process.env.OID_OBSERVER_DATABASE_URL.length > 0, 'observer_database_url_required');
  const Pool = await connectPg(repoRoot);
  const observerUrl = process.env.OID_OBSERVER_DATABASE_URL;
  const source = await liveSnapshot(Pool, observerUrl, sourceDatabase, 'source');
  const normal = await liveSnapshot(Pool, observerUrl, normalDatabase, 'normal_clone', result.reportCases?.reportId);
  const expired = await liveSnapshot(Pool, observerUrl, expiredDatabase, 'expired_clone');
  const sourceResult = compareSource(source, expectedSource);
  const normalResult = compareClone(normal, expectedNormal, 'normal_clone');
  const expiredResult = compareClone(expired, expectedExpired, 'expired_clone');
  const sourceImageFiles = await verifyUploadFiles(privateRoots.source, source.imageUploads, 'source');
  compareImageMetadata(sourceImageFiles.metadata, expectedSource.imageFiles, 'source');
  const normalImageFiles = await verifyUploadFiles(privateRoots.normal, normal.imageUploads, 'normal_clone');
  compareImageMetadata(normalImageFiles.metadata, expectedNormal.imageFiles, 'normal_clone');
  const expiredImageFiles = await verifyUploadFiles(privateRoots.expired, expired.imageUploads, 'expired_clone');
  compareImageMetadata(expiredImageFiles.metadata, expectedExpired.imageFiles, 'expired_clone');
  const expiredDirectory = await assertExpiredImageDirectoryEmpty(privateRoots.expired);
  const reportResult = await verifyNormalReport(normal, result, document, repoRoot, sourceDatabase);
  reportResult.sourceImageFilesVerified = sourceImageFiles.verifiedFiles;
  reportResult.normalCloneImageFilesVerified = normalImageFiles.verifiedFiles;
  const expiryResult = await verifyExpiredRetention(expired, expectedExpired,
    { verifiedFiles: expiredImageFiles.verifiedFiles, expiredDirectory });
  assert(expiryResult.financialStatePreserved && expiryResult.benchmarkGradesPreserved,
    'expired_clone_financial_or_benchmark_preservation_mismatch');

  const summary = { status: 'verified', boundary: 'independent_readonly_post_capture_replay',
    captureFileSha256: captureSha256, source: sourceResult, normalClone: normalResult,
    expiredClone: expiryResult,
    officialEvidence: { checkpointManifestSha256: officialManifestSha256,
      normalClone: normalOfficialEvidence, expiredClone: expiredOfficialEvidence },
    normalReport: reportResult, noDatabaseWrites: true };
  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
}

main().catch((error) => {
  const code = typeof error?.code === 'string' && /^[a-z0-9_]+$/.test(error.code)
    ? error.code : 'combined_live_verification_failed';
  process.stdout.write(JSON.stringify({ status: 'failed', errorCode: code }) + '\n');
  process.exitCode = 1;
});




