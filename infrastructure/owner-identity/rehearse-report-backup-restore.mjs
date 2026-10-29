import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  copyFile, link, lstat, mkdir, open, readFile, readdir, realpath, unlink, writeFile
} from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { inspectBackupFile, validateBackupInventory, verifyBackupFiles } from './beta-backup-inventory.mjs';

const SOURCE_DATABASE = 'oid_acceptance_1cd165376c254469960b85ef058ab3ca';
const SOURCE_CAPTURE_ID = '1cd16537-6c25-4469-960b-85ef058ab3ca';
const CAPTURE_BASE = '/local-report-captures';
const DAY_MS = 86_400_000;
const sourceRoot = resolve(CAPTURE_BASE, SOURCE_DATABASE);
const workspaceRoot = '/workspace';
const sourceImageRoot = resolve(sourceRoot, 'private-data', 'reports', 'images');
const { Client: PgClient } = createRequire(resolve(workspaceRoot, 'packages/owner-acceptance/package.json'))('pg');

function fail(code) { throw new Error(`sc022_report_restore_${code}`); }
function hashBytes(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonical(value) { return JSON.stringify(value); }
function safeDatabase(value, kind) {
  if (kind === 'source' && value !== SOURCE_DATABASE) fail('source_database_rejected');
  if (kind === 'restore' && !/^oid_restore_[a-f0-9]{32}$/.test(value ?? '')) fail('restore_database_rejected');
  return value;
}
function formatUuid(hex) { return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; }
function safeRelativePath(value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0') || isAbsolute(value) ||
      /^[A-Za-z]:/.test(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) fail('unsafe_relative_path');
  return value;
}
function quoteIdentifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) fail('unexpected_database_identifier');
  return `"${value}"`;
}
function assertTimestamp(value) {
  if (value !== null && (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
      Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value)) fail('invalid_closure_time');
  return value;
}
function requireHash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('invalid_hash');
  return value;
}
function contentWithin(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith('--') || index + 1 >= argv.length) fail('invalid_arguments');
    values[key.slice(2)] = argv[++index];
  }
  const phase = values.phase;
  if (!['preflight', 'verify-preflight', 'finalize', 'verify-restore', 'prepare-expired', 'cleanup-expired', 'finalize-expired'].includes(phase)) fail('invalid_phase');
  safeDatabase(values['source-database'], 'source');
  if (values['restore-database']) safeDatabase(values['restore-database'], 'restore');
  if (values['expired-database']) safeDatabase(values['expired-database'], 'restore');
  const checkpointId = values['checkpoint-id'];
  if (!/^[a-f0-9]{32}$/.test(checkpointId ?? '')) fail('invalid_checkpoint_id');
  const artifactRelative = safeRelativePath(values['artifact-relative']);
  const allowedRoot = resolve(workspaceRoot, '.local/owner-identity/report-restore-rehearsals');
  const artifactRoot = resolve(workspaceRoot, artifactRelative);
  if (!contentWithin(allowedRoot, artifactRoot) || artifactRoot === allowedRoot) fail('artifact_path_rejected');
  return { phase, checkpointId, artifactRelative, artifactRoot,
    restoreDatabase: values['restore-database'], expiredDatabase: values['expired-database'] };
}

function secretForRole(role) {
  const name = role === 'oid_owner' ? 'owner_password' : role === 'oid_observer' ? 'observer_password' : null;
  if (!name) fail('database_role_rejected');
  return readFile(`/run/secrets/${name}`, 'utf8').then((value) => value.trim());
}

async function databaseUrl(role, databaseName, applicationName) {
  const password = await secretForRole(role);
  const url = new URL('postgres://postgres:5432/');
  url.username = role;
  url.password = password;
  url.hostname = 'postgres';
  url.port = '5432';
  url.pathname = `/${databaseName}`;
  url.searchParams.set('application_name', applicationName);
  return url.href;
}

async function connect(role, databaseName, applicationName) {
  const client = new PgClient({ connectionString: await databaseUrl(role, databaseName, applicationName),
    connectionTimeoutMillis: 10_000, query_timeout: 120_000, statement_timeout: 120_000 });
  await client.connect();
  return client;
}

async function beginReadOnly(client) {
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const identity = (await client.query(`SELECT current_database() AS database,current_user AS role,
    current_setting('transaction_read_only') AS read_only,transaction_timestamp() AS snapshot_at`)).rows[0];
  if (!identity || identity.read_only !== 'on') fail('read_only_transaction_missing');
  return identity;
}

async function verifyIdentities(owner, observer, databaseName) {
  const ownerIdentity = await beginReadOnly(owner);
  const observerIdentity = await beginReadOnly(observer);
  if (ownerIdentity.database !== databaseName || ownerIdentity.role !== 'oid_owner') fail('owner_database_identity_mismatch');
  if (observerIdentity.database !== databaseName || observerIdentity.role !== 'oid_observer' || observerIdentity.read_only !== 'on') {
    fail('observer_database_identity_mismatch');
  }
  return { ownerIdentity, observerIdentity };
}

async function assertQuiescent(owner, allowedPids) {
  const result = await owner.query(`SELECT count(*)::int AS other_client_sessions,
      count(*) FILTER (WHERE state='active')::int AS active_sessions,
      count(*) FILTER (WHERE xact_start IS NOT NULL AND xact_start < clock_timestamp()-interval '5 seconds')::int AS long_transactions
    FROM pg_stat_activity WHERE datname=current_database() AND backend_type='client backend'
      AND NOT (pid = ANY($1::int[]))`, [allowedPids]);
  const row = result.rows[0];
  if (!row || row.other_client_sessions !== 0 || row.active_sessions !== 0 || row.long_transactions !== 0) {
    fail('source_database_not_quiescent');
  }
  return row;
}

async function fingerprintDatabase(client) {
  const tables = (await client.query(`SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename COLLATE "C"`))
    .rows.map((row) => row.tablename);
  const fingerprints = {};
  for (const table of tables) {
    const identifier = quoteIdentifier(table);
    const row = (await client.query(`SELECT count(*)::text AS row_count,
      encode(sha256(convert_to(coalesce(string_agg(row_text,E'\\n' ORDER BY row_text COLLATE "C"),''),'UTF8')),'hex') AS sha256
      FROM (SELECT row_to_json(t)::text AS row_text FROM public.${identifier} AS t) AS rows`)).rows[0];
    const count = Number(row?.row_count);
    if (!Number.isSafeInteger(count) || count > 100_000 || !/^[0-9a-f]{64}$/.test(row?.sha256 ?? '')) fail('table_fingerprint_out_of_bounds');
    fingerprints[table] = { rows: count, sha256: row.sha256 };
  }
  const sequences = (await client.query(`SELECT schemaname,sequencename,data_type,start_value,min_value,max_value,
      increment_by,cycle,cache_size,last_value::text AS last_value FROM pg_sequences
    WHERE schemaname='public' ORDER BY schemaname COLLATE "C",sequencename COLLATE "C"`)).rows;
  return { tables: fingerprints, sequences };
}

function canonicalFingerprints(value) {
  return canonical({ tables: Object.fromEntries(Object.entries(value.tables).sort(([a], [b]) => a.localeCompare(b, 'en'))),
    sequences: value.sequences });
}

async function reportState(client) {
  const reports = Number((await client.query('SELECT count(*)::text AS count FROM oid_support_report')).rows[0]?.count);
  const uploads = (await client.query(`SELECT id::text AS id,status,report_id::text AS report_id,storage_key::text AS storage_key,
      output_bytes,output_sha256,output_mime FROM oid_support_image_upload ORDER BY id`)).rows;
  const rawImageChunkRows = Number((await client.query('SELECT count(*)::text AS count FROM oid_support_image_chunk')).rows[0]?.count);
  const deletionReceipts = (await client.query(`SELECT report_id::text AS report_id,purge_status AS status
    FROM oid_support_report_deletion_receipt ORDER BY report_id`)).rows
    .map((row) => ({ reportId: row.report_id, status: row.status }));
  const gc = (await client.query(`SELECT status,count(*)::int AS count FROM oid_support_upload_gc_receipt GROUP BY status`)).rows;
  if (!Number.isSafeInteger(rawImageChunkRows) || rawImageChunkRows !== 0) fail('raw_image_chunks_prevent_checkpoint');
  for (const upload of uploads) {
    if (upload.status === 'receiving' || upload.status === 'processing') fail('active_upload_prevents_checkpoint');
    if (upload.storage_key) {
      if (!['ready', 'attached'].includes(upload.status) || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(upload.storage_key) ||
          !Number.isSafeInteger(upload.output_bytes) || upload.output_bytes < 1 || !/^[0-9a-f]{64}$/.test(upload.output_sha256 ?? '') || upload.output_mime !== 'image/webp') {
        fail('image_metadata_unreconciled');
      }
      if ((upload.status === 'attached') !== (upload.report_id !== null)) fail('image_report_binding_unreconciled');
    }
  }
  if (deletionReceipts.some((row) => row.status !== 'complete') || gc.some((row) => row.status === 'pending' || row.status === 'failed')) {
    fail('pending_storage_deletion_prevents_checkpoint');
  }
  return { reports, uploads, deletionReceipts, gc, rawImageChunkRows };
}

async function readClosureFile(path) {
  const info = await lstat(path).catch(() => fail('authoritative_closure_missing'));
  if (!info.isFile() || info.isSymbolicLink()) fail('authoritative_closure_unsafe');
  let state;
  try { state = JSON.parse(await readFile(path, 'utf8')); } catch { fail('authoritative_closure_invalid'); }
  if (!state || state.schemaVersion !== 'beta-report-closure-state/v1' || !Object.hasOwn(state, 'betaEndedAt') ||
      !/^[0-9a-f]{64}$/.test(state.sourceEvidenceSha256 ?? '') ||
      Object.keys(state).some((key) => !['schemaVersion', 'betaEndedAt', 'sourceEvidenceSha256'].includes(key))) fail('authoritative_closure_invalid');
  state.betaEndedAt = assertTimestamp(state.betaEndedAt);
  return state;
}

async function sourceProvenance() {
  const runsRoot = resolve(workspaceRoot, 'artifacts/runs/acceptance/BPC-SC-018/runs');
  const entries = await readdir(runsRoot, { withFileTypes: true }).catch(() => fail('source_capture_provenance_missing'));
  const matches = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^[0-9a-f-]{36}$/.test(entry.name)) continue;
    const directory = resolve(runsRoot, entry.name);
    let runtimeEvidence;
    try { runtimeEvidence = JSON.parse(await readFile(resolve(directory, 'runtime-evidence.json'), 'utf8')); } catch { continue; }
    if (runtimeEvidence.observer?.databaseName !== SOURCE_DATABASE) continue;
    const provenancePath = resolve(directory, 'provenance.json');
    let provenance;
    try { provenance = JSON.parse(await readFile(provenancePath, 'utf8')); } catch { fail('source_capture_provenance_missing'); }
    if (provenance.runId !== SOURCE_CAPTURE_ID || provenance.sourceStableDuringRun !== true ||
        !provenance.inputHashesBefore || !provenance.inputHashesAfter || provenance.contract?.sha256 !== provenance.contractSha256) {
      fail('source_capture_provenance_mismatch');
    }
    const before = Object.entries(provenance.inputHashesBefore).sort(([a], [b]) => a.localeCompare(b, 'en'));
    const after = Object.entries(provenance.inputHashesAfter).sort(([a], [b]) => a.localeCompare(b, 'en'));
    if (!before.length || canonical(before) !== canonical(after) || before.some(([path, hash]) =>
      !path || path.includes('\\') || path.split('/').some((part) => !part || part === '.' || part === '..') || !/^[0-9a-f]{64}$/.test(hash))) {
      fail('source_capture_provenance_mismatch');
    }
    matches.push({ provenance, provenancePath, inputEntries: before });
  }
  if (matches.length !== 1) fail('source_capture_provenance_ambiguous');
  const selected = matches[0];
  const sourceBuildSha256 = hashBytes(Buffer.from(canonical(selected.inputEntries), 'utf8'));
  const bytes = await readFile(selected.provenancePath);
  return { sourceBuildSha256, bytes, inputCount: selected.inputEntries.length,
    contractSha256: selected.provenance.contractSha256 };
}

async function rehearsalImplementationHashes() {
  const hashes = {};
  const addFile = async (relativePath) => {
    const absolute = resolve(workspaceRoot, relativePath);
    const info = await lstat(absolute).catch(() => fail('rehearsal_source_missing'));
    if (!info.isFile() || info.isSymbolicLink()) fail('rehearsal_source_unsafe');
    hashes[relativePath] = hashBytes(await readFile(absolute));
  };
  const addTree = async (relativeRoot) => {
    const absoluteRoot = resolve(workspaceRoot, relativeRoot);
    const walk = async (directory, prefix) => {
      const entries = await readdir(directory, { withFileTypes: true }).catch(() => fail('rehearsal_source_missing'));
      for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
        const relativePath = `${prefix}/${entry.name}`;
        const absolute = resolve(workspaceRoot, relativePath);
        if (entry.isSymbolicLink()) fail('rehearsal_source_unsafe');
        if (entry.isDirectory()) await walk(absolute, relativePath);
        else if (entry.isFile()) await addFile(relativePath);
        else fail('rehearsal_source_unsafe');
      }
    };
    await walk(absoluteRoot, relativeRoot);
  };
  await addTree('packages/owner-identity/src');
  for (const path of [
    'packages/owner-identity/package.json',
    'pnpm-lock.yaml',
    'infrastructure/owner-identity/rehearse-report-backup-restore.ps1',
    'infrastructure/owner-identity/rehearse-report-backup-restore.mjs',
    'infrastructure/owner-identity/beta-backup-inventory.mjs'
  ]) await addFile(path);
  return Object.fromEntries(Object.entries(hashes).sort(([a], [b]) => a.localeCompare(b, 'en')));
}

function implementationHashesSha256(hashes) {
  return hashBytes(Buffer.from(canonical(hashes), 'utf8'));
}

async function assertDirectoryChain(path) {
  const absolute = resolve(path);
  const root = await realpath(path).catch(() => fail('private_storage_missing'));
  let current = absolute;
  while (true) {
    const info = await lstat(current).catch(() => fail('private_storage_missing'));
    if (info.isSymbolicLink()) fail('private_storage_symlink');
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  if (root !== absolute) fail('private_storage_path_mismatch');
  return root;
}

async function hashRegularFile(root, path) {
  const resolvedRoot = await realpath(root);
  let target = resolvedRoot;
  const relPath = safeRelativePath(path);
  for (const part of relPath.split('/')) {
    target = resolve(target, part);
    const info = await lstat(target).catch(() => fail('referenced_image_missing'));
    if (info.isSymbolicLink()) fail('referenced_image_symlink');
  }
  const canonicalPath = await realpath(target).catch(() => fail('referenced_image_missing'));
  if (!contentWithin(resolvedRoot, canonicalPath)) fail('referenced_image_escape');
  const info = await lstat(canonicalPath);
  if (!info.isFile()) fail('referenced_image_not_regular');
  const handle = await open(canonicalPath, 'r').catch(() => fail('referenced_image_unreadable'));
  try {
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ino !== after.ino || bytes.length !== after.size) fail('referenced_image_changed');
    return { bytes, size: after.size, sha256: hashBytes(bytes) };
  } finally { await handle.close(); }
}

async function listTreeFiles(root, relativeRoot = '') {
  const absolute = relativeRoot ? resolve(root, ...relativeRoot.split('/')) : root;
  const entries = await readdir(absolute, { withFileTypes: true }).catch((error) => {
    if (error?.code === 'ENOENT') return [];
    fail('private_storage_unreadable');
  });
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) fail('private_storage_symlink');
    const rel = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await listTreeFiles(root, rel));
    else if (entry.isFile()) files.push(rel);
    else fail('private_storage_unsupported_entry');
  }
  return files;
}

async function imageReferencesAndFiles(reportRows, imageRoot, copyRoot) {
  const refs = reportRows.uploads.filter((upload) => upload.storage_key);
  const expected = new Set(refs.map((upload) => `${upload.storage_key}.webp`));
  const present = await listTreeFiles(imageRoot);
  if (present.some((path) => path.endsWith('.partial') || !expected.has(path)) ||
      expected.size !== present.length) fail('image_directory_reference_mismatch');
  const files = [];
  for (const upload of refs) {
    const name = `${upload.storage_key}.webp`;
    const observed = await hashRegularFile(imageRoot, name);
    if (observed.size !== upload.output_bytes || observed.sha256 !== upload.output_sha256) fail('image_bytes_hash_mismatch');
    if (upload.status === 'attached' && !reportRows.uploads.some((row) => row.id === upload.id && row.report_id)) fail('attached_image_report_missing');
    if (copyRoot) {
      const target = resolve(copyRoot, name);
      if (!contentWithin(resolve(copyRoot), target)) fail('image_copy_path_escape');
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      try { await copyFile(resolve(imageRoot, name), target, 1); } catch { fail('image_copy_failed'); }
      const copy = await hashRegularFile(copyRoot, name);
      if (copy.sha256 !== observed.sha256 || copy.size !== observed.size) fail('image_copy_hash_mismatch');
    }
    files.push({ path: `private-data/reports/images/${name}`, kind: 'screenshot', bytes: observed.size, sha256: observed.sha256 });
  }
  return files;
}

async function loadSnapshot(databaseName, expectedRole = 'oid_owner') {
  const owner = await connect('oid_owner', databaseName, `sc022-${expectedRole}-snapshot`);
  const observer = await connect('oid_observer', databaseName, 'sc022-observer-snapshot');
  try {
    const { ownerIdentity, observerIdentity } = await verifyIdentities(owner, observer, databaseName);
    if (expectedRole === 'oid_owner' && databaseName === SOURCE_DATABASE) await assertQuiescent(owner, [owner.processID, observer.processID]);
    const fingerprints = await fingerprintDatabase(owner);
    const reportRows = await reportState(owner);
    await observer.query('COMMIT');
    await owner.query('COMMIT');
    return { database: databaseName, snapshotAt: new Date(ownerIdentity.snapshot_at).toISOString(),
      observerIdentity: { database: observerIdentity.database, role: observerIdentity.role, readOnly: observerIdentity.read_only },
      fingerprints, reportRows };
  } catch (error) {
    await Promise.all([owner.query('ROLLBACK').catch(() => undefined), observer.query('ROLLBACK').catch(() => undefined)]);
    throw error;
  } finally { await Promise.all([owner.end(), observer.end()]); }
}

function fingerprintHash(snapshot) { return hashBytes(Buffer.from(canonicalFingerprints(snapshot.fingerprints), 'utf8')); }
function tableRows(snapshot, tableName) { return snapshot.fingerprints.tables[tableName]?.rows ?? null; }

async function writeJsonExclusive(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let handle;
  try {
    handle = await open(temp, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    // A hard link creates the destination atomically and fails with EEXIST; unlike rename,
    // it cannot replace an earlier evidence file on Linux.
    await link(temp, path);
    await unlink(temp);
    const directory = await open(dirname(path), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    await handle?.close().catch(() => undefined);
    await unlink(temp).catch(() => undefined);
    fail('artifact_write_failed');
  }
  return { bytes: bytes.length, sha256: hashBytes(bytes) };
}

async function copyClosureSidecar(closure, destination) {
  await writeJsonExclusive(destination, closure);
}

async function preflight(input) {
  const captureRootInfo = await assertDirectoryChain(sourceRoot);
  if (!contentWithin(await realpath(CAPTURE_BASE), captureRootInfo)) fail('source_capture_root_escape');
  await assertDirectoryChain(resolve(sourceRoot, 'private-data'));
  const closure = await readClosureFile(resolve(sourceRoot, 'beta-report-closure-state.json'));
  const sourceClosureSha256 = hashBytes(await readFile(resolve(sourceRoot, 'beta-report-closure-state.json')));
  const provenance = await sourceProvenance();
  const implementationHashes = await rehearsalImplementationHashes();
  const snapshot = await loadSnapshot(SOURCE_DATABASE);
  const imageCopyRoot = resolve(input.artifactRoot, 'bundle/private-data/reports/images');
  const imageFiles = await imageReferencesAndFiles(snapshot.reportRows, sourceImageRoot, imageCopyRoot);
  const provenancePath = resolve(input.artifactRoot, 'bundle/evidence/report-capture-provenance.json');
  await mkdir(dirname(provenancePath), { recursive: true, mode: 0o700 });
  try { await writeFile(provenancePath, provenance.bytes, { flag: 'wx', mode: 0o600 }); }
  catch { fail('provenance_copy_failed'); }
  const closureOutput = resolve(input.artifactRoot, 'operator/closure-state-at-capture.json');
  await copyClosureSidecar(closure, closureOutput);
  const summary = {
    schemaVersion: 'bpc-report-backup-source-snapshot/v1',
    boundary: 'local_unserved_acceptance_database_read_only',
    sourceDatabase: SOURCE_DATABASE,
    sourceCaptureId: SOURCE_CAPTURE_ID,
    snapshotAt: snapshot.snapshotAt,
    sourceObserverIdentity: snapshot.observerIdentity,
    sourceBuildSha256: provenance.sourceBuildSha256,
    captureSourceInputMapSha256: provenance.sourceBuildSha256,
    sourceBuildSha256Basis: 'sha256(canonical sorted path/hash map from stable local capture provenance; not a target image digest)',
    provenanceInputs: provenance.inputCount,
    captureContractSha256: provenance.contractSha256,
    rehearsalImplementationHashes: implementationHashes,
    rehearsalImplementationSha256: implementationHashesSha256(implementationHashes),
    betaEndedAt: closure.betaEndedAt,
    databaseTotalsSha256: fingerprintHash(snapshot),
    tableFingerprints: snapshot.fingerprints,
    reportCount: snapshot.reportRows.reports,
    uploadRows: snapshot.reportRows.uploads.length,
    rawImageChunkRows: snapshot.reportRows.rawImageChunkRows,
    imageFiles,
    deletionReceipts: snapshot.reportRows.deletionReceipts,
    uploadGcStatuses: snapshot.reportRows.gc,
    benchmarkRuns: tableRows(snapshot, 'oid_benchmark_run'),
    ledgerEntries: tableRows(snapshot, 'oid_ledger_entry'),
    bonusFixture: 'not_seeded_by_this_report_capture',
    sourceClosureSha256,
    closureCopySha256: hashBytes(await readFile(closureOutput))
  };
  const file = await writeJsonExclusive(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), summary);
  return { summary, snapshot, closure, provenance, imageFiles, sourceBeforeSha256: file.sha256 };
}

async function verifyPreflight(input) {
  const evidencePath = resolve(input.artifactRoot, 'bundle/evidence/source-before.json');
  const before = JSON.parse(await readFile(evidencePath, 'utf8'));
  const closureCopy = JSON.parse(await readFile(resolve(input.artifactRoot, 'operator/closure-state-at-capture.json'), 'utf8'));
  if (before.schemaVersion !== 'bpc-report-backup-source-snapshot/v1' || before.sourceDatabase !== SOURCE_DATABASE ||
      before.sourceCaptureId !== SOURCE_CAPTURE_ID || before.boundary !== 'local_unserved_acceptance_database_read_only' ||
      closureCopy.betaEndedAt !== before.betaEndedAt ||
      hashBytes(await readFile(resolve(input.artifactRoot, 'operator/closure-state-at-capture.json'))) !== before.closureCopySha256) {
    fail('preflight_evidence_invalid');
  }
  const current = await loadSnapshot(SOURCE_DATABASE);
  const closure = await readClosureFile(resolve(sourceRoot, 'beta-report-closure-state.json'));
  const provenance = await sourceProvenance();
  const implementationHashes = await rehearsalImplementationHashes();
  const images = await imageReferencesAndFiles(current.reportRows, sourceImageRoot);
  if (fingerprintHash(current) !== before.databaseTotalsSha256 || closure.betaEndedAt !== before.betaEndedAt ||
      hashBytes(await readFile(resolve(sourceRoot, 'beta-report-closure-state.json'))) !== before.sourceClosureSha256 ||
      provenance.sourceBuildSha256 !== before.sourceBuildSha256 ||
      provenance.contractSha256 !== before.captureContractSha256 || canonical(images) !== canonical(before.imageFiles) ||
      canonical(implementationHashes) !== canonical(before.rehearsalImplementationHashes) ||
      implementationHashesSha256(implementationHashes) !== before.rehearsalImplementationSha256) {
    fail('source_changed_since_preflight');
  }
  const bundleRoot = resolve(input.artifactRoot, 'bundle');
  for (const image of before.imageFiles) {
    const copy = await hashRegularFile(bundleRoot, image.path);
    if (copy.sha256 !== image.sha256 || copy.size !== image.bytes) fail('preflight_image_copy_changed');
  }
  return {
    status: 'revalidated',
    sourceStable: true,
    sourceDatabase: SOURCE_DATABASE,
    sourceCaptureId: SOURCE_CAPTURE_ID,
    boundary: 'local_unserved_acceptance_database_read_only',
    sourceObserverIdentity: current.observerIdentity,
    publicTableCount: Object.keys(current.fingerprints.tables).length,
    databaseTotalsSha256: fingerprintHash(current),
    sourceBeforeEvidenceSha256: hashBytes(await readFile(evidencePath)),
    captureSourceInputMapSha256: provenance.sourceBuildSha256,
    rehearsalImplementationSha256: implementationHashesSha256(implementationHashes),
    sourceClosureSha256: before.sourceClosureSha256,
    reportCount: current.reportRows.reports,
    uploadRows: current.reportRows.uploads.length,
    rawImageChunkRows: current.reportRows.rawImageChunkRows,
    screenshotCount: images.length,
    screenshotBytes: images.reduce((total, image) => total + image.bytes, 0)
  };
}

async function snapshotForFinalize() {
  const snapshot = await loadSnapshot(SOURCE_DATABASE);
  const closure = await readClosureFile(resolve(sourceRoot, 'beta-report-closure-state.json'));
  return { snapshot, closure };
}

async function finalize(input) {
  const before = JSON.parse(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), 'utf8'));
  const { snapshot: after, closure } = await snapshotForFinalize();
  const implementationHashes = await rehearsalImplementationHashes();
  if (after.snapshotAt < before.snapshotAt || fingerprintHash(after) !== before.databaseTotalsSha256 ||
      closure.betaEndedAt !== before.betaEndedAt ||
      hashBytes(await readFile(resolve(sourceRoot, 'beta-report-closure-state.json'))) !== before.sourceClosureSha256 ||
      hashBytes(await readFile(resolve(input.artifactRoot, 'operator/closure-state-at-capture.json'))) !== before.closureCopySha256 ||
      canonical(implementationHashes) !== canonical(before.rehearsalImplementationHashes) ||
      implementationHashesSha256(implementationHashes) !== before.rehearsalImplementationSha256) {
    fail('source_changed_during_checkpoint');
  }
  const currentCopyRoot = resolve(input.artifactRoot, 'bundle/private-data/reports/images');
  const copiedFiles = await listTreeFiles(currentCopyRoot);
  const expectedFiles = before.imageFiles.map((row) => row.path.replace('private-data/reports/images/', ''));
  if (canonical([...copiedFiles].sort()) !== canonical([...expectedFiles].sort())) fail('copied_image_set_mismatch');
  const imageRefs = await imageReferencesAndFiles(after.reportRows, sourceImageRoot);
  if (canonical(imageRefs) !== canonical(before.imageFiles)) fail('source_image_set_changed');
  const imageFiles = before.imageFiles;
  const databaseFile = await inspectBackupFile(resolve(input.artifactRoot, 'bundle'), 'database.dump.enc', 'database');
  if (databaseFile.bytes === 0) fail('database_dump_missing');
  const afterFile = await writeJsonExclusive(resolve(input.artifactRoot, 'bundle/evidence/source-after.json'), {
    schemaVersion: 'bpc-report-backup-source-after/v1', sourceDatabase: SOURCE_DATABASE,
    sourceCaptureId: SOURCE_CAPTURE_ID, snapshotAt: after.snapshotAt, databaseTotalsSha256: fingerprintHash(after),
    tableFingerprints: after.fingerprints, reportCount: after.reportRows.reports,
    uploadRows: after.reportRows.uploads.length, rawImageChunkRows: after.reportRows.rawImageChunkRows,
    imageFiles, sourceStable: true,
    rehearsalImplementationHashes: implementationHashes,
    rehearsalImplementationSha256: implementationHashesSha256(implementationHashes)
  });
  const reconciliation = {
    schemaVersion: 'bpc-report-backup-reconciliation/v1',
    boundary: 'local_unserved_acceptance_database_read_only',
    sourceDatabase: SOURCE_DATABASE,
    sourceCaptureId: SOURCE_CAPTURE_ID,
    checkpointId: input.checkpointId,
    sourceBeforeSnapshotAt: before.snapshotAt,
    sourceAfterSnapshotAt: after.snapshotAt,
    sourceStable: true,
    sourceBuildSha256: before.sourceBuildSha256,
    sourceBuildSha256Basis: before.sourceBuildSha256Basis,
    captureSourceInputMapSha256: before.sourceBuildSha256,
    databaseTotalsSha256: before.databaseTotalsSha256,
    screenshotCount: before.imageFiles.length,
    screenshotsBytes: before.imageFiles.reduce((total, file) => total + file.bytes, 0),
    reportCount: before.reportCount,
    codeBonusRunRestoreProof: 'not_present_in_report_only_source_fixture',
    sourceBeforeEvidenceSha256: hashBytes(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'))),
    sourceClosureSha256: before.sourceClosureSha256,
    sourceAfterEvidenceSha256: afterFile.sha256,
    rehearsalImplementationSha256: implementationHashesSha256(implementationHashes),
    encryptedDatabaseDumpSha256: databaseFile.sha256
  };
  const reconciliationFile = await writeJsonExclusive(resolve(input.artifactRoot, 'bundle/evidence/reconciliation.json'), reconciliation);
  const provenanceFile = await inspectBackupFile(resolve(input.artifactRoot, 'bundle'), 'evidence/report-capture-provenance.json', 'evidence');
  const sourceBeforeFile = await inspectBackupFile(resolve(input.artifactRoot, 'bundle'), 'evidence/source-before.json', 'evidence');
  const sourceAfterFile = await inspectBackupFile(resolve(input.artifactRoot, 'bundle'), 'evidence/source-after.json', 'evidence');
  const reconciliationEntry = await inspectBackupFile(resolve(input.artifactRoot, 'bundle'), 'evidence/reconciliation.json', 'evidence');
  const screenshotFiles = before.imageFiles;
  const now = new Date().toISOString();
  const inventory = {
    schemaVersion: 'beta-backup-inventory/v1',
    checkpointId: formatUuid(input.checkpointId),
    kind: 'daily',
    failureDomain: 'same_host',
    sourceBuildSha256: before.sourceBuildSha256,
    sourceBuildSha256Basis: before.sourceBuildSha256Basis,
    capturedAt: before.snapshotAt,
    betaEndedAt: before.betaEndedAt,
    reconciliationEvidenceSha256: reconciliationFile.sha256,
    databaseTotalsSha256: before.databaseTotalsSha256,
    reportDeletionReceipts: before.deletionReceipts,
    files: [databaseFile, provenanceFile, sourceBeforeFile, sourceAfterFile, reconciliationEntry, ...screenshotFiles]
  };
  validateBackupInventory(inventory);
  const verified = await verifyBackupFiles(resolve(input.artifactRoot, 'bundle'), inventory, {
    now, authoritativeBetaEndedAt: closure.betaEndedAt
  });
  await writeJsonExclusive(resolve(input.artifactRoot, 'bundle/inventory.json'), inventory);
  await writeJsonExclusive(resolve(input.artifactRoot, 'bundle/file-verification.json'), verified);
  return { inventory, verified, reconciliation, sourceStable: true };
}

async function copyBundleImagesToRestore(input, databaseName, restoreRootRelative, closure) {
  const restoreRoot = resolve(input.artifactRoot, restoreRootRelative);
  const privateRoot = resolve(restoreRoot, 'private-data');
  const copyRoot = resolve(privateRoot, 'reports', 'images');
  const bundleRoot = resolve(input.artifactRoot, 'bundle');
  const inventory = JSON.parse(await readFile(resolve(bundleRoot, 'inventory.json'), 'utf8'));
  const screenshotEntries = inventory.files.filter((file) => file.kind === 'screenshot');
  for (const row of screenshotEntries) {
    const rel = safeRelativePath(row.path);
    const observed = await hashRegularFile(bundleRoot, rel);
    if (observed.sha256 !== row.sha256 || observed.size !== row.bytes) fail('bundle_image_hash_mismatch');
    const name = rel.split('/').at(-1);
    const destination = resolve(copyRoot, name);
    if (!contentWithin(copyRoot, destination)) fail('restore_image_path_escape');
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    try { await copyFile(resolve(bundleRoot, rel), destination, 1); } catch { fail('restore_image_copy_failed'); }
  }
  const operatorRoot = resolve(restoreRoot, 'operator');
  await mkdir(operatorRoot, { recursive: true, mode: 0o700 });
  await copyClosureSidecar(closure, resolve(operatorRoot, 'authoritative-closure.json'));
  const files = await imageReferencesAndFiles((await loadSnapshot(databaseName)).reportRows, copyRoot);
  if (canonical(files) !== canonical(screenshotEntries)) fail('restore_image_reconciliation_failed');
  return { restoreRoot, privateRoot, screenshotCount: files.length,
    screenshotBytes: files.reduce((total, file) => total + file.bytes, 0), files };
}

async function runIdempotentReportRetry(databaseName, reportClosurePath, privateDataDir) {
  const client = await connect('oid_owner', databaseName, 'sc022-report-restore-retry-read');
  let candidate;
  try {
    candidate = (await client.query(`SELECT r.id::text AS id,r.owner_id::text AS owner_id,r.agent_id::text AS agent_id,
        r.reporter_kind,r.reporter_id::text AS reporter_id,r.operation_id,r.title,r.body,r.client_version,
        r.run_id::text AS run_id,r.task_id,r.action_id::text AS action_id,count(u.id)::int AS image_count
      FROM oid_support_report r LEFT JOIN oid_support_image_upload u ON u.report_id=r.id AND u.status='attached'
      GROUP BY r.id HAVING count(u.id)=0 ORDER BY r.created_at,r.id LIMIT 1`)).rows[0];
  } finally { await client.end(); }
  if (!candidate) fail('report_retry_candidate_missing');
  const { createDatabase } = await import('../../packages/owner-identity/src/db.ts');
  const { createReportClosureStateStore } = await import('../../packages/owner-identity/src/report-closure-state.ts');
  const { createSupportReport } = await import('../../packages/owner-identity/src/report-service.ts');
  const db = createDatabase({ databaseUrl: await databaseUrl('oid_owner', databaseName, 'sc022-report-restore-retry-service') });
  try {
    const actor = { kind: candidate.reporter_kind, ownerId: candidate.owner_id,
      ...(candidate.reporter_kind === 'agent' ? { agentId: candidate.reporter_id } : {}), requestId: 'sc022-local-restore-retry' };
    const input = {
      operationId: candidate.operation_id,
      title: candidate.title,
      body: candidate.body,
      imageUploadIds: []
    };
    for (const [key, value] of Object.entries({
      agentId: candidate.agent_id,
      runId: candidate.run_id,
      taskId: candidate.task_id,
      actionId: candidate.action_id,
      clientVersion: candidate.client_version
    })) {
      if (typeof value === 'string' && value.length > 0) input[key] = value;
    }
    const result = await createSupportReport({ db: db.db, privateDataDir, reportClosureState: createReportClosureStateStore(reportClosurePath) }, actor, input);
    if (!result.replayed || result.report?.id !== candidate.id) fail('idempotent_report_retry_identity_mismatch');
    return { status: 'verified', boundary: 'direct_service_retry_in_isolated_restore_database', reportRowsReplayed: 1 };
  } finally { await db.client.end({ timeout: 5 }); }
}

async function verifyRestore(input) {
  const restoreDatabase = safeDatabase(input.restoreDatabase, 'restore');
  const sourceBefore = JSON.parse(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), 'utf8'));
  const closure = JSON.parse(await readFile(resolve(input.artifactRoot, 'operator/closure-state-at-capture.json'), 'utf8'));
  const restore = await loadSnapshot(restoreDatabase);
  if (fingerprintHash(restore) !== sourceBefore.databaseTotalsSha256) fail('restored_table_or_sequence_fingerprint_mismatch');
  const copied = await copyBundleImagesToRestore(input, restoreDatabase, `restore/${restoreDatabase}`, closure);
  const retry = await runIdempotentReportRetry(restoreDatabase,
    resolve(copied.restoreRoot, 'operator/authoritative-closure.json'), copied.privateRoot);
  const afterRetry = await loadSnapshot(restoreDatabase);
  if (fingerprintHash(afterRetry) !== sourceBefore.databaseTotalsSha256) fail('restore_retry_changed_database');
  const sourceAfter = await loadSnapshot(SOURCE_DATABASE);
  if (fingerprintHash(sourceAfter) !== sourceBefore.databaseTotalsSha256) fail('source_changed_during_restore');
  const summary = {
    schemaVersion: 'bpc-report-backup-restore-rehearsal/v1',
    boundary: 'local_isolated_report_backup_restore',
    checkpointId: formatUuid(input.checkpointId),
    sourceDatabase: SOURCE_DATABASE,
    restoreDatabase,
    sourceUnchanged: true,
    sourceFingerprintMatchesCheckpoint: true,
    restoredTablesAndSequencesMatch: true,
    restoredScreenshotCount: copied.screenshotCount,
    restoredScreenshotBytes: copied.screenshotBytes,
    reportRetry: retry,
    restoredApplicationStarted: false,
    writesMayBeEnabled: false,
    bonusAndBenchmarkRunRestoration: 'not_proven_by_report_only_source_capture',
    targetHostAcceptance: 'not_run'
  };
  await writeJsonExclusive(resolve(input.artifactRoot, 'restore/restore-verification.json'), summary);
  return summary;
}

async function prepareExpired(input) {
  const expiredDatabase = safeDatabase(input.expiredDatabase, 'restore');
  const expiredRoot = resolve(input.artifactRoot, `expired-clone/${expiredDatabase}`);
  const sourceBefore = JSON.parse(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), 'utf8'));
  const closure = JSON.parse(await readFile(resolve(input.artifactRoot, 'operator/closure-state-at-capture.json'), 'utf8'));
  const current = await loadSnapshot(expiredDatabase);
  const reportRows = current.reportRows;
  const unlinkedActive = reportRows.uploads.some((upload) => upload.report_id === null && upload.storage_key && upload.status === 'ready');
  if (reportRows.reports === 0 || unlinkedActive) {
    const summary = { schemaVersion: 'bpc-report-expired-clone/v1', status: 'not_run',
      reasonCode: reportRows.reports === 0 ? 'no_report_rows_in_source' : 'unlinked_ready_upload_not_expirable_by_report_retention',
      sourceDatabase: SOURCE_DATABASE, expiredDatabase, writesMayBeEnabled: false };
    await writeJsonExclusive(resolve(expiredRoot, 'expired-rehearsal.json'), summary);
    return summary;
  }
  const privateRoot = resolve(expiredRoot, 'private-data');
  const bundleRoot = resolve(input.artifactRoot, 'bundle');
  const inventory = JSON.parse(await readFile(resolve(bundleRoot, 'inventory.json'), 'utf8'));
  const screenshotEntries = inventory.files.filter((file) => file.kind === 'screenshot');
  for (const row of screenshotEntries) {
    const rel = safeRelativePath(row.path);
    const sourceFile = await hashRegularFile(bundleRoot, rel);
    if (sourceFile.sha256 !== row.sha256 || sourceFile.size !== row.bytes) fail('bundle_image_hash_mismatch');
    const destination = resolve(privateRoot, 'reports', 'images', rel.split('/').at(-1));
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    try { await copyFile(resolve(bundleRoot, rel), destination, 1); } catch { fail('expired_clone_image_copy_failed'); }
  }
  const past = new Date(Date.now() - 31 * DAY_MS).toISOString();
  const syntheticClosure = { schemaVersion: 'beta-report-closure-state/v1', betaEndedAt: past,
    sourceEvidenceSha256: hashBytes(Buffer.from(`synthetic-expired-clone:${input.checkpointId}`, 'utf8')) };
  const closureFile = resolve(expiredRoot, 'operator', 'synthetic-expired-closure.json');
  await copyClosureSidecar(syntheticClosure, closureFile);
  const result = { schemaVersion: 'bpc-report-expired-clone/v1', status: 'prepared',
    boundary: 'synthetic_clone_only_backdated_authoritative_closure', sourceDatabase: SOURCE_DATABASE,
    expiredDatabase, syntheticBetaEndedAt: past, sourceClosureUnchanged: true, sourceDatabaseUnchanged: true,
    reportCountBeforeCleanup: reportRows.reports, imageCountBeforeCleanup: reportRows.uploads.filter((row) => row.storage_key).length,
    privateDataDir: privateRoot, closureFile, sourceClosureWasCopied: closure.betaEndedAt !== past, writesMayBeEnabled: false };
  await writeJsonExclusive(resolve(expiredRoot, 'expired-input.json'), result);
  return result;
}

async function cloneOnlyRetentionCleanup(input) {
  const expiredDatabase = safeDatabase(input.expiredDatabase, 'restore');
  const expiredRoot = resolve(input.artifactRoot, `expired-clone/${expiredDatabase}`);
  const privateRoot = resolve(expiredRoot, 'private-data');
  const closureFile = resolve(expiredRoot, 'operator', 'synthetic-expired-closure.json');
  const before = await loadSnapshot(expiredDatabase);
  const checkpoint = JSON.parse(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), 'utf8'));
  if (checkpoint.schemaVersion !== 'bpc-report-backup-source-snapshot/v1' || checkpoint.sourceDatabase !== SOURCE_DATABASE ||
      checkpoint.sourceCaptureId !== SOURCE_CAPTURE_ID || checkpoint.boundary !== 'local_unserved_acceptance_database_read_only') {
    fail('source_checkpoint_identity_invalid');
  }
  const closureCopyPath = resolve(input.artifactRoot, 'operator/closure-state-at-capture.json');
  const closureCopyBytes = await readFile(closureCopyPath);
  if (hashBytes(closureCopyBytes) !== checkpoint.closureCopySha256) fail('source_checkpoint_closure_copy_mismatch');
  const sourceBeforeCleanup = await loadSnapshot(SOURCE_DATABASE);
  const sourceImagesBefore = await imageReferencesAndFiles(sourceBeforeCleanup.reportRows, sourceImageRoot);
  const sourceClosurePath = resolve(sourceRoot, 'beta-report-closure-state.json');
  const sourceClosureBeforeHash = hashBytes(await readFile(sourceClosurePath));
  if (fingerprintHash(sourceBeforeCleanup) !== checkpoint.databaseTotalsSha256 ||
      sourceClosureBeforeHash !== checkpoint.sourceClosureSha256 || canonical(sourceImagesBefore) !== canonical(checkpoint.imageFiles)) {
    fail('source_changed_since_checkpoint');
  }
  const { createDatabase } = await import('../../packages/owner-identity/src/db.ts');
  const { createReportClosureStateStore } = await import('../../packages/owner-identity/src/report-closure-state.ts');
  const { runReportRetentionCleanup } = await import('../../packages/owner-identity/src/report-service.ts');
  const db = createDatabase({ databaseUrl: await databaseUrl('oid_owner', expiredDatabase, 'sc022-expired-clone-cleanup') });
  let iterations = 0;
  try {
    for (; iterations < 25; iterations += 1) {
      await runReportRetentionCleanup({ db: db.db, privateDataDir: privateRoot,
        reportClosureState: createReportClosureStateStore(closureFile) });
      const current = await loadSnapshot(expiredDatabase);
      const pendingReceipts = current.reportRows.deletionReceipts.some((row) => row.status !== 'complete');
      const pendingGc = current.reportRows.gc.some((row) => row.status === 'pending' || row.status === 'failed');
      const activeImages = current.reportRows.uploads.some((row) => row.storage_key !== null);
      const files = await listTreeFiles(resolve(privateRoot, 'reports', 'images'));
      if (current.reportRows.reports === 0 && current.reportRows.uploads.length === 0 && !pendingReceipts && !pendingGc && !activeImages && files.length === 0) break;
    }
  } finally { await db.client.end({ timeout: 5 }); }
  const after = await loadSnapshot(expiredDatabase);
  if (after.reportRows.reports !== 0 || after.reportRows.uploads.length !== 0 || after.reportRows.deletionReceipts.some((row) => row.status !== 'complete') ||
      after.reportRows.gc.some((row) => row.status === 'pending' || row.status === 'failed') ||
      (await listTreeFiles(resolve(privateRoot, 'reports', 'images'))).length !== 0) fail('expired_clone_retention_cleanup_incomplete');
  const protectedTables = Object.keys(before.fingerprints.tables).filter((table) => !table.startsWith('oid_support_'));
  for (const table of protectedTables) {
    if (canonical(before.fingerprints.tables[table]) !== canonical(after.fingerprints.tables[table])) fail('expired_clone_changed_non_report_table');
  }
  const protectedSequences = before.fingerprints.sequences.filter((sequence) => !sequence.sequencename.startsWith('oid_support_'));
  const afterProtectedSequences = after.fingerprints.sequences.filter((sequence) => !sequence.sequencename.startsWith('oid_support_'));
  const nonReportSequencesUnchanged = canonical(protectedSequences) === canonical(afterProtectedSequences);
  if (!nonReportSequencesUnchanged) fail('expired_clone_changed_non_report_sequence');
  const closure = JSON.parse(await readFile(closureFile, 'utf8'));
  const receiptRows = after.reportRows.deletionReceipts;
  const expectedDeletedReports = before.reportRows.reports;
  if (receiptRows.length < expectedDeletedReports || receiptRows.some((row) => row.status !== 'complete')) fail('expired_clone_deletion_receipts_incomplete');
  const sourceAfterCleanup = await loadSnapshot(SOURCE_DATABASE);
  const sourceClosureAfterHash = hashBytes(await readFile(sourceClosurePath));
  const sourceImagesAfter = await imageReferencesAndFiles(sourceAfterCleanup.reportRows, sourceImageRoot);
  const sourceDatabaseUnchanged = fingerprintHash(sourceAfterCleanup) === checkpoint.databaseTotalsSha256;
  const sourceClosureUnchanged = sourceClosureAfterHash === checkpoint.sourceClosureSha256;
  const sourceImagesUnchanged = canonical(sourceImagesAfter) === canonical(checkpoint.imageFiles);
  const summary = {
    schemaVersion: 'bpc-report-expired-clone/v1',
    status: 'synthetic_retention_cleanup_verified',
    boundary: 'clone_only_backdated_authoritative_closure_and_report_service_cleanup',
    sourceDatabase: SOURCE_DATABASE,
    expiredDatabase,
    syntheticBetaEndedAt: closure.betaEndedAt,
    cleanupIterations: iterations + 1,
    reportsBefore: before.reportRows.reports,
    reportsAfter: after.reportRows.reports,
    uploadsBefore: before.reportRows.uploads.length,
    uploadsAfter: after.reportRows.uploads.length,
    deletionReceipts: receiptRows.length,
    failedOrPendingReportReceipts: 0,
    pendingOrFailedUploadGcReceipts: 0,
    remainingImageFiles: 0,
    nonReportTablesUnchanged: true,
    nonReportSequencesUnchanged,
    sourceDatabaseUnchanged,
    sourceClosureUnchanged,
    sourceImagesUnchanged,
    sourceWasNeverBackdated: true,
    officialGradesAndLedger: 'not_proven_by_report_only_source_fixture',
    writesMayBeEnabled: false
  };
  await writeJsonExclusive(resolve(expiredRoot, 'expired-rehearsal.json'), summary);
  if (!summary.sourceDatabaseUnchanged || !summary.sourceClosureUnchanged || !summary.sourceImagesUnchanged) {
    fail('source_changed_during_expired_clone_cleanup');
  }
  return summary;
}

async function finalizeExpired(input) {
  const expiredDatabase = safeDatabase(input.expiredDatabase, 'restore');
  const root = resolve(input.artifactRoot, `expired-clone/${expiredDatabase}`);
  const closure = JSON.parse(await readFile(resolve(root, 'operator/synthetic-expired-closure.json'), 'utf8'));
  const proofPath = resolve(root, 'expired-rehearsal.json');
  const proof = JSON.parse(await readFile(proofPath, 'utf8'));
  if (proof.status !== 'synthetic_retention_cleanup_verified' || proof.reportsAfter !== 0 || proof.uploadsAfter !== 0 || proof.remainingImageFiles !== 0) {
    fail('expired_clone_proof_missing');
  }
  const databaseFile = await inspectBackupFile(root, 'database.dump.enc', 'database');
  const proofFile = await inspectBackupFile(root, 'expired-rehearsal.json', 'evidence');
  const sanitizedHash = hashBytes(await readFile(proofPath));
  const sourceBefore = JSON.parse(await readFile(resolve(input.artifactRoot, 'bundle/evidence/source-before.json'), 'utf8'));
  const inventory = {
    schemaVersion: 'beta-backup-inventory/v1', checkpointId: formatUuid(input.checkpointId), kind: 'retention_sanitized',
    failureDomain: 'same_host', sourceBuildSha256: sourceBefore.sourceBuildSha256,
    sourceBuildSha256Basis: sourceBefore.sourceBuildSha256Basis,
    capturedAt: new Date().toISOString(), betaEndedAt: closure.betaEndedAt,
    reconciliationEvidenceSha256: proofFile.sha256, databaseTotalsSha256: fingerprintHash(await loadSnapshot(expiredDatabase)),
    sanitizationEvidenceSha256: sanitizedHash, reportDeletionReceipts: (await loadSnapshot(expiredDatabase)).reportRows.deletionReceipts,
    files: [databaseFile, proofFile]
  };
  validateBackupInventory(inventory);
  const verified = await verifyBackupFiles(root, inventory, { authoritativeBetaEndedAt: closure.betaEndedAt });
  await writeJsonExclusive(resolve(root, 'inventory.json'), inventory);
  await writeJsonExclusive(resolve(root, 'file-verification.json'), verified);
  return { status: 'synthetic_sanitized_inventory_verified', inventory, verified,
    boundary: 'clone_only_backdated_closure_not_target_retention_acceptance' };
}

async function main() {
  const allowedWorkingDirectories = [workspaceRoot, resolve(workspaceRoot, 'packages/owner-identity')];
  if (process.platform !== 'linux' || !allowedWorkingDirectories.includes(resolve(process.cwd()))) fail('pinned_runtime_required');
  const input = parseArgs(process.argv.slice(2));
  if (input.phase === 'preflight') return preflight(input);
  if (input.phase === 'verify-preflight') return verifyPreflight(input);
  if (input.phase === 'finalize') return finalize(input);
  if (input.phase === 'verify-restore') return verifyRestore(input);
  if (input.phase === 'prepare-expired') return prepareExpired(input);
  if (input.phase === 'cleanup-expired') return cloneOnlyRetentionCleanup(input);
  return finalizeExpired(input);
}

try {
  const result = await main();
  const phase = process.argv[process.argv.indexOf('--phase') + 1];
  const output = phase === 'preflight' ? {
    phase,
    summary: {
      schemaVersion: result.summary.schemaVersion,
      boundary: result.summary.boundary,
      sourceDatabase: result.summary.sourceDatabase,
      sourceCaptureId: result.summary.sourceCaptureId,
      snapshotAt: result.summary.snapshotAt,
      sourceObserverIdentity: result.summary.sourceObserverIdentity,
      sourceBuildSha256: result.summary.sourceBuildSha256,
      captureSourceInputMapSha256: result.summary.captureSourceInputMapSha256,
      sourceBuildSha256Basis: result.summary.sourceBuildSha256Basis,
      provenanceInputs: result.summary.provenanceInputs,
      captureContractSha256: result.summary.captureContractSha256,
      rehearsalImplementationSha256: result.summary.rehearsalImplementationSha256,
      rehearsalImplementationFileCount: Object.keys(result.summary.rehearsalImplementationHashes).length,
      betaEndedAt: result.summary.betaEndedAt,
      databaseTotalsSha256: result.summary.databaseTotalsSha256,
      publicTableCount: Object.keys(result.summary.tableFingerprints.tables).length,
      reportCount: result.summary.reportCount,
      uploadRows: result.summary.uploadRows,
      rawImageChunkRows: result.summary.rawImageChunkRows,
      screenshotCount: result.summary.imageFiles.length,
      screenshotBytes: result.summary.imageFiles.reduce((total, file) => total + file.bytes, 0),
      uploadGcStatuses: result.summary.uploadGcStatuses,
      benchmarkRuns: result.summary.benchmarkRuns,
      ledgerEntries: result.summary.ledgerEntries,
      bonusFixture: result.summary.bonusFixture,
      sourceClosureSha256: result.summary.sourceClosureSha256
    }
  } : phase === 'verify-preflight' ? { phase, ...result } : { phase, ...result };
  process.stdout.write(`${JSON.stringify(output)}\n`);
} catch (error) {
  const code = error instanceof Error && /^sc022_report_restore_[a-z0-9_]+$/.test(error.message)
    ? error.message : 'sc022_report_restore_internal_failure';
  process.stderr.write(`${JSON.stringify({ phase: process.argv[process.argv.indexOf('--phase') + 1] ?? 'unknown', errorCode: code })}\n`);
  process.exitCode = 1;
}
