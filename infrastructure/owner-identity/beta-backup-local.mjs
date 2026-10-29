import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { inspectBackupFile, validateBackupInventory, verifyBackupIntegrity } from './beta-backup-inventory.mjs';
import { createCombinedCheckpoint } from './beta-backup-checkpoint.mjs';
import { restoreCombinedCheckpoint, verifyCombinedRestoreRetryProof } from './beta-backup-restore.mjs';
import { openSealedCheckpointPayload } from './beta-backup-sealed-bundle.mjs';
import { createEphemeralRecoveryKeyPair, decryptBridgedRecoveryMaterial, protectRecoveryMaterial } from './beta-backup-recovery-envelope.mjs';
import { runDailyBackupScheduler } from './beta-backup-scheduler.mjs';

const HASH = /^[0-9a-f]{64}$/;
const UUID_HEX = /^[0-9a-f]{32}$/;

function fail(code) { throw new Error(`beta_backup_local_${code}`); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function delay(ms) { return new Promise((resolveDelay) => setTimeout(resolveDelay, ms)); }
function sourceDbName(urlValue) {
  let url;
  try { url = new URL(urlValue); } catch { fail('database_url_invalid'); }
  const name = decodeURIComponent(url.pathname.slice(1));
  if (!/^[A-Za-z0-9_]{1,63}$/.test(name)) fail('database_name_invalid');
  return name;
}
function within(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function withDatabase(urlValue, databaseName) {
  const url = new URL(urlValue);
  url.pathname = `/${databaseName}`;
  return url.href;
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function quoteIdentifier(value) { return `"${String(value).replaceAll('"', '""')}"`; }
function groupHash(tableFingerprints, predicate) {
  return sha256(Buffer.from(canonical(Object.fromEntries(Object.entries(tableFingerprints).filter(([name]) => predicate(name))))));
}
function isBenchmarkTable(name) {
  return name === 'oid_benchmark_run' || name.startsWith('oid_run_') || name.startsWith('oid_task_') || name.startsWith('oid_ranked_');
}
export function benchmarkStateFingerprint(tableFingerprints) {
  if (!tableFingerprints || typeof tableFingerprints !== 'object' || Array.isArray(tableFingerprints)) {
    fail('benchmark_table_fingerprints_invalid');
  }
  return groupHash(tableFingerprints, isBenchmarkTable);
}
function assertSecrets(value) {
  const keys = ['authSecret', 'bonusCodeVerifierSecret', 'googleClientId', 'googleClientSecret'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || keys.some((key) => typeof value[key] !== 'string' || value[key].length < 16)) {
    fail('runtime_recovery_secrets_missing');
  }
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

async function assertSafePathPrefix(path) {
  const absolute = resolve(path);
  let current = parse(absolute).root;
  const parts = relative(current, absolute).split(sep).filter(Boolean);
  for (let index = 0; index < parts.length; index += 1) {
    current = resolve(current, parts[index]);
    let info;
    try { info = await lstat(current); } catch (error) {
      if (error?.code === 'ENOENT') return absolute;
      throw error;
    }
    if (info.isSymbolicLink() || (index < parts.length - 1 && !info.isDirectory())) fail('path_prefix_unsafe');
  }
  return realpath(absolute);
}

function createPg(repoRoot) {
  const require = createRequire(resolve(repoRoot, 'packages/owner-acceptance/package.json'));
  let Pool;
  try { ({ Pool } = require('pg')); } catch { fail('pinned_pg_driver_missing'); }
  return Pool;
}

async function databaseSnapshot({ Pool, databaseUrl, databaseName, sourceBuildSha256, boundaryId }) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 1_000 });
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = (await client.query(`SELECT current_database() AS database_name,current_user AS database_role,
      current_setting('transaction_read_only') AS transaction_read_only,clock_timestamp() AS observed_at`)).rows[0];
    if (!identity || identity.database_name !== databaseName || identity.database_role !== 'oid_observer' || identity.transaction_read_only !== 'on') {
      fail('observer_identity_mismatch');
    }
    const relationRows = (await client.query(`SELECT c.relname AS table_name FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname`)).rows;
    if (!relationRows.length) fail('public_table_inventory_empty');
    const tableFingerprints = {};
    for (const { table_name: tableName } of relationRows) {
      const rows = (await client.query(`SELECT to_jsonb(t)::text AS row_json FROM public.${quoteIdentifier(tableName)} AS t`)).rows;
      const rowJson = rows.map((row) => row.row_json).sort();
      const hash = createHash('sha256');
      for (const value of rowJson) { hash.update(value); hash.update('\n'); }
      tableFingerprints[tableName] = { rowCount: rowJson.length, sha256: hash.digest('hex') };
    }
    const sequences = (await client.query(`SELECT schemaname,sequencename,last_value FROM pg_sequences WHERE schemaname='public' ORDER BY schemaname,sequencename`)).rows;
    const sequenceSha256 = sha256(Buffer.from(canonical(sequences)));
    const databaseTotalsSha256 = sha256(Buffer.from(canonical({ tableFingerprints, sequenceSha256 })));
    const requiredTables = ['oid_benchmark_run', 'oid_run_operation', 'oid_ledger_operation', 'oid_bonus_code_claim_operation',
      'oid_task_preparation_generation', 'oid_support_report', 'oid_support_report_audit', 'oid_support_image_upload',
      'oid_support_report_deletion_receipt', 'oid_support_upload_gc_receipt', 'oid_support_report_rate'];
    if (requiredTables.some((name) => !Object.hasOwn(tableFingerprints, name))) fail('required_domain_table_missing');
    const query = async (sqlText) => (await client.query(sqlText)).rows;
    const completedRunIds = (await query(`SELECT id::text FROM oid_benchmark_run WHERE status='completed' ORDER BY id`)).map((row) => row.id);
    const queuedInterruptedUnknownRunIds = (await query(`SELECT id::text FROM oid_benchmark_run
      WHERE status IN ('queued','preparing','running','cancellation_requested','unknown') ORDER BY id`)).map((row) => row.id);
    const runOperations = await query(`SELECT operation_id FROM oid_run_operation ORDER BY operation_id`);
    const bonusLedgerOperations = await query(`SELECT operation_id FROM oid_ledger_operation WHERE action='bonus_grant' ORDER BY operation_id`);
    const bonusClaims = await query(`SELECT operation_id FROM oid_bonus_code_claim_operation ORDER BY operation_id`);
    const reportOperations = await query(`SELECT operation_id FROM oid_support_report WHERE operation_id IS NOT NULL ORDER BY operation_id`);
    const reportAuditOperations = await query(`SELECT operation_id FROM oid_support_report_audit WHERE operation_id IS NOT NULL ORDER BY operation_id`);
    const operationIds = [...new Set([...runOperations, ...bonusLedgerOperations, ...bonusClaims, ...reportOperations, ...reportAuditOperations]
      .map((row) => row.operation_id))].sort();
    const bonusGrantOperationIds = [...new Set([...bonusLedgerOperations, ...bonusClaims].map((row) => row.operation_id))].sort();
    const reportOperationIds = [...new Set([...reportOperations, ...reportAuditOperations].map((row) => row.operation_id))].sort();
    const imageRows = await query(`SELECT storage_key::text,output_bytes,output_sha256 FROM oid_support_image_upload
      WHERE status IN ('ready','attached') AND storage_key IS NOT NULL ORDER BY storage_key`);
    const imageFiles = imageRows.map((row) => ({ path: `private-data/reports/images/${row.storage_key}.webp`,
      bytes: Number(row.output_bytes), sha256: row.output_sha256 }));
    const reportDeletionReceipts = (await query(`SELECT report_id::text,purge_status FROM oid_support_report_deletion_receipt ORDER BY report_id`))
      .map((row) => ({ reportId: row.report_id, status: row.purge_status }));
    const countRows = await query(`SELECT (SELECT count(*)::int FROM oid_support_report) AS report_count,
      (SELECT count(*)::int FROM oid_support_image_upload) AS upload_count,
      (SELECT count(*)::int FROM oid_ledger_operation) AS ledger_operation_count,
      (SELECT count(*)::int FROM oid_bonus_code_claim_operation) AS bonus_claim_count,
      (SELECT count(*)::int FROM oid_run_operation) AS run_operation_count,
      (SELECT count(*)::int FROM oid_task_preparation_generation) AS generation_count,
      (SELECT count(*)::int FROM oid_support_report) + (SELECT count(*)::int FROM oid_support_report_audit) AS report_operation_count,
      (SELECT count(*)::int FROM oid_support_upload_gc_receipt WHERE status IN ('pending','failed')) AS pending_upload_gc_count`);
    const counts = countRows[0];
    const operationBindings = {
      bonusGrantOperationsSha256: groupHash(tableFingerprints, (name) => name === 'oid_ledger_operation' || name === 'oid_bonus_code_claim_operation'),
      bonusGrantOperationCount: bonusLedgerOperations.length + bonusClaims.length,
      runOperationReceiptsSha256: tableFingerprints.oid_run_operation.sha256,
      runOperationReceiptCount: counts.run_operation_count,
      runGenerationReceiptsSha256: tableFingerprints.oid_task_preparation_generation.sha256,
      runGenerationReceiptCount: counts.generation_count,
      reportOperationReceiptsSha256: groupHash(tableFingerprints, (name) => name === 'oid_support_report' || name === 'oid_support_report_audit'),
      reportOperationReceiptCount: counts.report_operation_count,
    };
    const tableNames = Object.keys(tableFingerprints);
    const financialStateSha256 = groupHash(tableFingerprints, (name) => name.startsWith('oid_ledger_') || name.startsWith('oid_bonus_') || name === 'oid_run_reservation' || name === 'oid_run_budget_hold');
    const benchmarkStateSha256 = benchmarkStateFingerprint(tableFingerprints);
    const financialNames = (name) => name.startsWith('oid_ledger_') || name.startsWith('oid_bonus_') || name === 'oid_run_reservation' || name === 'oid_run_budget_hold';
    const benchmarkNames = isBenchmarkTable;
    const reportNames = new Set(['oid_support_report', 'oid_support_report_audit', 'oid_support_image_upload',
      'oid_support_image_chunk', 'oid_support_report_deletion_receipt', 'oid_support_upload_gc_receipt',
      'oid_support_image_input_usage', 'oid_support_report_retention_state']);
    const reportRateNames = new Set(['oid_support_report_rate']);
    const reportStateSha256 = groupHash(tableFingerprints, (name) => reportNames.has(name));
    const reportRateLimitStateSha256 = groupHash(tableFingerprints, (name) => reportRateNames.has(name));
    const controlOperationalStateSha256 = groupHash(tableFingerprints, (name) =>
      !financialNames(name) && !benchmarkNames(name) && !reportNames.has(name) && !reportRateNames.has(name));
    await client.query('COMMIT');
    return {
      schemaVersion: 'beta-combined-source-observation/v1', sourceDatabase: databaseName,
      observerIdentity: { databaseRole: identity.database_role, databaseName: identity.database_name, transactionReadOnly: identity.transaction_read_only },
      snapshotBoundary: 'admission_frozen_database_quiescent', snapshotBoundaryId: boundaryId,
      snapshotAt: new Date(identity.observed_at).toISOString(), sourceBuildSha256, tableFingerprints, sequenceSha256,
      databaseTotalsSha256, financialStateSha256, benchmarkStateSha256, reportStateSha256,
      reportRateLimitStateSha256, controlOperationalStateSha256,
      operationBindings, imageFiles, reportDeletionReceipts,
      reportCount: counts.report_count, uploadCount: counts.upload_count,
      pendingUploadGcReceipts: counts.pending_upload_gc_count,
      originalIds: { completedRunIds, queuedInterruptedUnknownRunIds, operationIds, bonusGrantOperationIds, reportOperationIds },
      _tableCount: tableNames.length,
    };
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client?.release();
    await pool.end();
  }
}

async function readDatabaseClock({ Pool, databaseUrl, databaseName }) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 1_000 });
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN READ ONLY');
    const row = (await client.query(`SELECT current_database() AS database_name,current_user AS database_role,
      current_setting('transaction_read_only') AS transaction_read_only,clock_timestamp() AS database_now`)).rows[0];
    if (!row || row.database_name !== databaseName || row.database_role !== 'oid_observer' || row.transaction_read_only !== 'on') {
      fail('database_clock_observer_identity_mismatch');
    }
    await client.query('COMMIT');
    return new Date(row.database_now).toISOString();
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally { client?.release(); await pool.end(); }
}

async function waitForHostJob({ repoRoot, hostBridgeRoot, kind, payload, prepareJob, timeoutMs = 600_000 }) {
  const jobId = randomUUID().replaceAll('-', '');
  const jobRoot = resolve(hostBridgeRoot, jobId);
  await mkdir(jobRoot, { recursive: false, mode: 0o700 });
  try {
    if (typeof prepareJob === 'function') await prepareJob({ jobId, jobRoot });
    const request = { schemaVersion: 'beta-backup-host-job/v1', jobId, kind, ...payload };
    const requestPath = resolve(jobRoot, 'request.json');
    const requestHandle = await open(requestPath, 'wx', 0o600);
    try { await requestHandle.writeFile(`${JSON.stringify(request)}\n`); await requestHandle.sync(); } finally { await requestHandle.close(); }
  } catch (error) {
    await rm(jobRoot, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
  const resultPath = resolve(jobRoot, 'result.json');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const result = JSON.parse(await readFile(resultPath, 'utf8'));
      if (result.schemaVersion !== 'beta-backup-host-result/v1' || result.jobId !== jobId || result.kind !== kind) fail('host_job_result_identity_mismatch');
      if (result.status !== 'complete') fail(`host_job_${result.errorCode ?? 'failed'}`);
      return { jobId, jobRoot, result };
    } catch (error) {
      if (String(error?.code ?? '') !== 'ENOENT') throw error;
    }
    await delay(250);
  }
  fail('host_job_timeout');
}

function makeKeyRecovery({ repoRoot, hostBridgeRoot, recoveryPublicKeyPath }) {
  return {
    async protectMaterial({ checkpointId, bundleKey, runtimeSecrets }) {
      return protectRecoveryMaterial({ checkpointId, bundleKey, runtimeSecrets,
        publicKeyPath: recoveryPublicKeyPath });
    },
    async recoverMaterial({ checkpointId, envelopePath, envelopeSha256 }) {
      const pair = createEphemeralRecoveryKeyPair();
      const { jobId, jobRoot } = await waitForHostJob({ repoRoot, hostBridgeRoot, kind: 'recover_material',
        payload: { checkpointId, envelopeRelativePath: 'recovery-envelope.json',
          ephemeralPublicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          responseRelativePath: 'recovered-material.enc' },
        prepareJob: async ({ jobRoot: path }) => {
          const bytes = await readFile(envelopePath);
          if (sha256(bytes) !== envelopeSha256) fail('external_recovery_envelope_changed');
          const handle = await open(resolve(path, 'recovery-envelope.json'), 'wx', 0o600);
          try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); bytes.fill(0); }
        } });
      let recovered = false;
      try {
        const encryptedMaterial = await readFile(resolve(jobRoot, 'recovered-material.enc'));
        const material = decryptBridgedRecoveryMaterial({ checkpointId, encryptedMaterial, ephemeralPrivateKey: pair.privateKey });
        recovered = true;
        return material;
      } finally {
        if (recovered) await rm(jobRoot, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  };
}

/** Concrete local provider used by the combined acceptance runner; the host broker owns fixed Compose calls. */
export async function createLocalCombinedBackup({ repoRoot, databaseUrl, observerDatabaseUrl, privateDataDir,
  closureStatePath, officialEvidenceRoot = repoRoot, sourceBuildSha256, officialEvidenceRefs,
  getRuntimeRecoverySecrets, stopApi, restartApi, hostBridgeRoot, hostOperatorRoot, backupRoot, restoreRoot,
  recoveryPublicKeyPath, recoveryPrivateKeyPath, checkpointId = randomUUID(), kind = 'pre_migration', checkpointBundleRoot }) {
  if (!isAbsolute(repoRoot ?? '') || typeof databaseUrl !== 'string' || typeof observerDatabaseUrl !== 'string' ||
      !isAbsolute(privateDataDir ?? '') || !isAbsolute(closureStatePath ?? '') || !isAbsolute(officialEvidenceRoot) ||
      !HASH.test(sourceBuildSha256 ?? '') || typeof getRuntimeRecoverySecrets !== 'function' ||
      typeof stopApi !== 'function' || typeof restartApi !== 'function' || typeof checkpointId !== 'string' ||
      !UUID_HEX.test(checkpointId.replaceAll('-', '')) || !isAbsolute(backupRoot ?? '') || !isAbsolute(restoreRoot ?? '') ||
      (hostBridgeRoot !== undefined && !isAbsolute(hostBridgeRoot)) ||
      (hostOperatorRoot !== undefined && !isAbsolute(hostOperatorRoot)) ||
      (recoveryPublicKeyPath !== undefined && !isAbsolute(recoveryPublicKeyPath)) ||
      (recoveryPrivateKeyPath !== undefined && !isAbsolute(recoveryPrivateKeyPath)) ||
      (checkpointBundleRoot !== undefined && !isAbsolute(checkpointBundleRoot))) fail('factory_input_invalid');
  const databaseName = sourceDbName(databaseUrl);
  if (sourceDbName(observerDatabaseUrl) !== databaseName) fail('observer_database_target_mismatch');
  const root = resolve(repoRoot);
  const localBackupRoot = resolve(backupRoot);
  const restoreBase = resolve(restoreRoot);
  const bridgeBase = resolve(hostBridgeRoot ?? root, hostBridgeRoot ? '' : '.local/beta-backup-jobs');
  const hostRoot = resolve(bridgeBase, checkpointId.replaceAll('-', ''));
  const operatorRoot = resolve(hostOperatorRoot ?? root, hostOperatorRoot ? '' : '.local/beta-backup-operator');
  const recoveryPub = resolve(recoveryPublicKeyPath ?? operatorRoot, recoveryPublicKeyPath ? '' : 'operator/operator-recovery-public.pem');
  const recoveryPriv = resolve(recoveryPrivateKeyPath ?? operatorRoot, recoveryPrivateKeyPath ? '' : 'operator/operator-recovery-private.dpapi');
  const checkpointHex = checkpointId.replaceAll('-', '');
  const checkpointDir = resolve(checkpointBundleRoot ?? resolve(localBackupRoot, 'checkpoints', checkpointHex));
  const recoveryDir = resolve(localBackupRoot, 'recovery');
  await assertSafePathPrefix(localBackupRoot);
  await assertSafePathPrefix(bridgeBase);
  await assertSafePathPrefix(hostRoot);
  await assertSafePathPrefix(operatorRoot);
  await assertSafePathPrefix(restoreBase);
  await assertSafePathPrefix(checkpointDir);
  if (checkpointBundleRoot !== undefined) {
    const canonicalBackupRoot = await assertSafePathPrefix(localBackupRoot);
    const canonicalStage = await assertSafePathPrefix(checkpointDir);
    if (canonicalStage !== resolve(canonicalBackupRoot, `.pending-${checkpointHex}`)) fail('scheduler_stage_path_invalid');
    const stageInfo = await lstat(canonicalStage);
    if (!stageInfo.isDirectory() || stageInfo.isSymbolicLink() || (await readdir(canonicalStage)).length !== 0) {
      fail('scheduler_stage_not_empty');
    }
  } else {
    await mkdir(resolve(localBackupRoot, 'checkpoints'), { recursive: true, mode: 0o700 });
  }
  await mkdir(recoveryDir, { recursive: true, mode: 0o700 });
  await mkdir(restoreBase, { recursive: true, mode: 0o700 });
  await mkdir(hostRoot, { recursive: true, mode: 0o700 });
  if (checkpointBundleRoot === undefined) await mkdir(checkpointDir, { recursive: false, mode: 0o700 });
  const externalKeyRecoveryPath = resolve(recoveryDir, `${checkpointId.replaceAll('-', '')}.envelope.json`);
  const Pool = createPg(root);
  const keyRecovery = makeKeyRecovery({ repoRoot: root, hostBridgeRoot: hostRoot, recoveryPublicKeyPath: recoveryPub });
  const getDatabaseNow = async () => readDatabaseClock({ Pool, databaseUrl: withDatabase(observerDatabaseUrl, databaseName), databaseName });
  const observer = (databaseNameValue) => databaseSnapshot({ Pool,
    databaseUrl: withDatabase(observerDatabaseUrl, databaseNameValue), databaseName: databaseNameValue,
    sourceBuildSha256, boundaryId: 'unbound' });
  const checkpointAdapters = {
    async acquireAdmissionFreeze() {
      await stopApi();
      return { status: 'frozen', admissionFrozen: true, leaseId: randomUUID(), boundaryId: randomUUID() };
    },
    async releaseAdmissionFreeze() { await restartApi(); },
    async assertQuiescent({ databaseName: targetDatabase }) {
      const pool = new Pool({ connectionString: withDatabase(databaseUrl, targetDatabase), max: 1, connectionTimeoutMillis: 5_000 });
      let client;
      try {
        client = await pool.connect();
        const identity = (await client.query('SELECT current_database() AS database_name,current_user AS database_role,pg_backend_pid() AS pid')).rows[0];
        if (identity.database_name !== targetDatabase || identity.database_role !== 'oid_owner') fail('owner_identity_mismatch');
        const row = (await client.query(`SELECT count(*)::int AS other_sessions,
          count(*) FILTER (WHERE state='active')::int AS active_sessions,
          count(*) FILTER (WHERE xact_start IS NOT NULL AND xact_start<clock_timestamp()-interval '5 seconds')::int AS long_transactions
          FROM pg_stat_activity WHERE datname=current_database() AND backend_type='client backend' AND pid<>$1`, [identity.pid])).rows[0];
        if (!row || row.other_sessions !== 0 || row.active_sessions !== 0 || row.long_transactions !== 0) fail('source_database_not_quiescent');
      } finally { client?.release(); await pool.end(); }
    },
    async observeReadOnly({ databaseName: targetDatabase, boundaryId }) {
      const value = await databaseSnapshot({ Pool, databaseUrl: withDatabase(observerDatabaseUrl, targetDatabase),
        databaseName: targetDatabase, sourceBuildSha256, boundaryId });
      delete value._tableCount;
      return value;
    },
    async streamDatabaseDump({ databaseName: targetDatabase }) {
      const job = await waitForHostJob({ repoRoot: root, hostBridgeRoot: hostRoot, kind: 'pg_dump',
        payload: { databaseName: targetDatabase, dumpRelativePath: 'database.dump' } });
      const dumpPath = resolve(job.jobRoot, 'database.dump');
      const dumpStream = createReadStream(dumpPath);
      dumpStream.once('close', () => { void rm(job.jobRoot, { recursive: true, force: true }); });
      return dumpStream;
    },
    async readOfficialEvidence() {
      const value = typeof officialEvidenceRefs === 'function' ? await officialEvidenceRefs() : officialEvidenceRefs;
      return { ...value, sourceBuildSha256: value?.sourceBuildSha256 ?? sourceBuildSha256 };
    },
    async getRuntimeRecoverySecrets() { return assertSecrets(await getRuntimeRecoverySecrets()); },
  };
  const restoreAdapters = {
    async databaseExists({ databaseName: targetDatabase }) {
      const { result, jobRoot } = await waitForHostJob({ repoRoot: root, hostBridgeRoot: hostRoot, kind: 'database_exists',
        payload: { databaseName: targetDatabase } });
      await rm(jobRoot, { recursive: true, force: true });
      return result.exists === true;
    },
    async createRestoreDatabase({ databaseName: targetDatabase, checkpointId }) {
      const { result, jobRoot } = await waitForHostJob({ repoRoot: root, hostBridgeRoot: hostRoot, kind: 'create_restore_database',
        payload: { databaseName: targetDatabase, checkpointId } });
      await rm(jobRoot, { recursive: true, force: true });
      return result;
    },
    async restoreDatabaseDump({ databaseName: targetDatabase, dumpPath, dumpSha256, checkpointId, creationJobId }) {
      const jobId = randomUUID().replaceAll('-', '');
      const jobRoot = resolve(hostRoot, jobId);
      await mkdir(jobRoot, { recursive: false, mode: 0o700 });
      const staged = resolve(jobRoot, 'restore.dump');
      const input = await readFile(dumpPath);
      if (sha256(input) !== dumpSha256) fail('restore_dump_hash_mismatch');
      const handle = await open(staged, 'wx', 0o600);
      try { await handle.writeFile(input); await handle.sync(); } finally { await handle.close(); input.fill(0); }
      const request = { schemaVersion: 'beta-backup-host-job/v1', jobId, kind: 'pg_restore',
        databaseName: targetDatabase, checkpointId, creationJobId,
        dumpRelativePath: 'restore.dump', dumpSha256 };
      const requestHandle = await open(resolve(jobRoot, 'request.json'), 'wx', 0o600);
      try { await requestHandle.writeFile(`${JSON.stringify(request)}\n`); await requestHandle.sync(); } finally { await requestHandle.close(); }
      const deadline = Date.now() + 600_000;
      let restored = false;
      try {
        while (Date.now() < deadline) {
          try {
            const result = JSON.parse(await readFile(resolve(jobRoot, 'result.json'), 'utf8'));
            if (result.schemaVersion !== 'beta-backup-host-result/v1' || result.jobId !== jobId || result.kind !== 'pg_restore' || result.status !== 'complete') fail('host_pg_restore_failed');
            if (result.databaseName !== targetDatabase || result.checkpointId !== checkpointId || result.creationJobId !== creationJobId ||
                result.dumpSha256 !== dumpSha256 || result.restored !== true) fail('host_pg_restore_receipt_invalid');
            restored = true;
            return { status: 'restored', databaseName: targetDatabase, dumpSha256 };
          } catch (error) { if (String(error?.code ?? '') !== 'ENOENT') throw error; }
          await delay(250);
        }
        fail('host_pg_restore_timeout');
      } finally {
        if (restored) await rm(jobRoot, { recursive: true, force: true }).catch(() => undefined);
        else await rm(staged, { force: true }).catch(() => undefined);
      }
    },
    async restorePrivateFiles({ payloadRoot, privateDataDir }) {
      const { copyFile, readdir, lstat, mkdir } = await import('node:fs/promises');
      const source = resolve(payloadRoot, 'private-data/reports/images');
      const target = resolve(privateDataDir, 'reports/images');
      await mkdir(target, { recursive: true, mode: 0o700 });
      const files = await readdir(source, { withFileTypes: true }).catch(() => []);
      let count = 0;
      for (const entry of files) {
        const info = await lstat(resolve(source, entry.name));
        if (!entry.isFile() || info.isSymbolicLink() || !/^[a-f0-9-]{36}\.webp$/.test(entry.name)) fail('restored_image_path_invalid');
        await copyFile(resolve(source, entry.name), resolve(target, entry.name), 1); count += 1;
      }
      return { status: 'restored', fileCount: count };
    },
    async observeReadOnly({ databaseName: targetDatabase }) {
      return databaseSnapshot({ Pool, databaseUrl: withDatabase(observerDatabaseUrl, targetDatabase),
        databaseName: targetDatabase, sourceBuildSha256, boundaryId: 'restore' });
    },
    async cleanupExpiredClone({ databaseName: targetDatabase, privateDataDir: clonePrivateDataDir, closureStatePath: cloneClosureStatePath,
      sourceCheckpointId }) {
      const registerRequire = createRequire(resolve(root, 'packages/owner-identity/package.json'));
      let register;
      try { ({ register } = registerRequire('tsx/esm/api')); register(); } catch { fail('tsx_runtime_hook_unavailable'); }
      const dbModule = await import(new URL('../../packages/owner-identity/src/db.ts', import.meta.url));
      const closureModule = await import(new URL('../../packages/owner-identity/src/report-closure-state.ts', import.meta.url));
      const reportModule = await import(new URL('../../packages/owner-identity/src/report-service.ts', import.meta.url));
      const targetUrl = withDatabase(databaseUrl, targetDatabase);
      const { createDatabase } = dbModule;
      const connection = createDatabase({ databaseUrl: targetUrl });
      try {
        const closure = closureModule.createReportClosureStateStore(cloneClosureStatePath);
        const before = await databaseSnapshot({ Pool, databaseUrl: withDatabase(observerDatabaseUrl, targetDatabase),
          databaseName: targetDatabase, sourceBuildSha256, boundaryId: 'expiry-before' });
        const cleanup = await reportModule.runReportRetentionCleanup({ db: connection.db, privateDataDir: clonePrivateDataDir,
          reportClosureState: closure });
        const after = await databaseSnapshot({ Pool, databaseUrl: withDatabase(observerDatabaseUrl, targetDatabase),
          databaseName: targetDatabase, sourceBuildSha256, boundaryId: 'expiry-after' });
        const receipts = after.reportDeletionReceipts;
        const receiptSha256 = sha256(Buffer.from(canonical(receipts)));
        return { status: 'complete', sourceCheckpointId, restoreDatabaseName: targetDatabase,
          cleanupReceiptSha256: receiptSha256, reportsDeleted: cleanup.reportsDeleted, uploadsCleaned: cleanup.uploadsCleaned,
          reportsAfter: after.reportCount, uploadsAfter: after.uploadCount, remainingImageFiles: after.imageFiles.length,
          failedReportReceipts: receipts.filter((row) => row.status === 'failed').length,
          pendingUploadGcReceipts: after.pendingUploadGcReceipts, financialStateBeforeSha256: before.financialStateSha256,
          financialStateAfterSha256: after.financialStateSha256, benchmarkStateBeforeSha256: before.benchmarkStateSha256,
          benchmarkStateAfterSha256: after.benchmarkStateSha256, reportStateBeforeSha256: before.reportStateSha256,
          reportStateAfterSha256: after.reportStateSha256 };
      } finally { await connection.client.end({ timeout: 5 }); }
    },
  };
  return {
    source: { databaseName, databaseUrl, observerDatabaseUrl, privateDataDir, closureStatePath, officialEvidenceRoot, sourceBuildSha256 },
    checkpoint: { checkpointId, kind, bundleRoot: checkpointDir, externalKeyRecoveryPath, authoritativeClosurePath: closureStatePath },
    restore: { restoreRoot: restoreBase,
      databaseUrlForRestore: ({ databaseName: targetDatabase }) => withDatabase(databaseUrl, targetDatabase) },
    checkpointAdapters, restoreAdapters, keyRecovery, hostJobRoot: hostRoot, hostOperatorRoot: operatorRoot,
    getDatabaseNow,
    now: new Date().toISOString(),
    createCheckpoint: (overrides = {}) => createCombinedCheckpoint({ source: { ...{ databaseName, privateDataDir, closureStatePath, officialEvidenceRoot, sourceBuildSha256 }, ...overrides.source },
      checkpoint: { checkpointId, kind, bundleRoot: checkpointDir, externalKeyRecoveryPath, ...overrides.checkpoint },
      adapters: checkpointAdapters, keyRecovery, now: overrides.now ?? new Date().toISOString() }),
    restoreCheckpoint: async (input = {}) => restoreCombinedCheckpoint({ source: { databaseName, databaseUrl, observerDatabaseUrl },
      checkpoint: { bundleRoot: checkpointDir, externalKeyRecoveryPath, authoritativeClosurePath: closureStatePath, ...input.checkpoint },
      restore: { restoreRoot: restoreBase,
        databaseUrlForRestore: ({ databaseName: targetDatabase }) => withDatabase(databaseUrl, targetDatabase), ...input.restore },
      adapters: restoreAdapters, keyRecovery, now: input.now ?? await getDatabaseNow(), retentionFixture: input.retentionFixture ?? null }),
    verifyCombinedRestoreRetryProof,
  };
}

async function readAuthoritativeClosure(closureStatePath) {
  if (!isAbsolute(closureStatePath ?? '')) fail('closure_path_invalid');
  const path = await assertSafePathPrefix(closureStatePath);
  const info = await lstat(path).catch(() => fail('closure_state_missing'));
  if (info.isSymbolicLink() || !info.isFile() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) {
    fail('closure_state_permissions_or_type_invalid');
  }
  let value;
  try { value = JSON.parse(await readFile(path, 'utf8')); } catch { fail('closure_state_invalid'); }
  const keys = Object.keys(value ?? {}).sort();
  if (canonical(keys) !== canonical(['betaEndedAt', 'schemaVersion', 'sourceEvidenceSha256']) ||
      value.schemaVersion !== 'beta-report-closure-state/v1' ||
      !(value.betaEndedAt === null || (typeof value.betaEndedAt === 'string' &&
        /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value.betaEndedAt) &&
        Number.isFinite(Date.parse(value.betaEndedAt)) && new Date(value.betaEndedAt).toISOString() === value.betaEndedAt)) ||
      !HASH.test(value.sourceEvidenceSha256 ?? '')) fail('closure_state_invalid');
  return value;
}

async function verifyLocalCheckpointOfficialSource({ providerOptions, checkpointDirectory, inventory }) {
  validateBackupInventory(inventory);
  if (inventory.schemaVersion !== 'beta-backup-inventory/v2' || inventory.files.length !== 1 ||
      inventory.files[0].kind !== 'sealed_bundle' || inventory.files[0].path !== 'checkpoint.bundle.enc' ||
      inventory.checkpointSource?.boundary !== 'admission_frozen_database_quiescent') fail('scheduler_checkpoint_shape_invalid');
  const repoRoot = resolve(providerOptions.repoRoot);
  const backupRoot = await assertSafePathPrefix(providerOptions.backupRoot);
  const bundleRoot = await assertSafePathPrefix(checkpointDirectory);
  const checkpointHex = inventory.checkpointId.replaceAll('-', '');
  const expectedNames = new Set([checkpointHex, `.pending-${checkpointHex}`]);
  const bundleName = relative(backupRoot, bundleRoot);
  if (!within(backupRoot, bundleRoot) || bundleName.includes(sep) || !expectedNames.has(bundleName)) {
    fail('scheduler_checkpoint_path_invalid');
  }
  const fileProof = await verifyBackupIntegrity(bundleRoot, inventory);
  if (fileProof.integrity !== 'passed' || fileProof.writesMayBeEnabled !== false) fail('scheduler_checkpoint_integrity_invalid');

  const recoveryDir = resolve(backupRoot, 'recovery');
  const externalKeyRecoveryPath = resolve(recoveryDir, `${checkpointHex}.envelope.json`);
  const canonicalRecoveryDir = await assertSafePathPrefix(recoveryDir);
  const canonicalEnvelope = await assertSafePathPrefix(externalKeyRecoveryPath);
  if (!within(backupRoot, canonicalRecoveryDir) || !within(canonicalRecoveryDir, canonicalEnvelope)) fail('scheduler_recovery_path_invalid');
  const bridgeBase = resolve(providerOptions.hostBridgeRoot ?? repoRoot, providerOptions.hostBridgeRoot ? '' : '.local/beta-backup-jobs');
  const hostRoot = resolve(bridgeBase, checkpointHex);
  await assertSafePathPrefix(bridgeBase);
  await assertSafePathPrefix(hostRoot);
  await mkdir(hostRoot, { recursive: true, mode: 0o700 });
  const operatorRoot = resolve(providerOptions.hostOperatorRoot ?? repoRoot,
    providerOptions.hostOperatorRoot ? '' : '.local/beta-backup-operator');
  const recoveryPublicKeyPath = resolve(providerOptions.recoveryPublicKeyPath ?? operatorRoot,
    providerOptions.recoveryPublicKeyPath ? '' : 'operator/operator-recovery-public.pem');
  const keyRecovery = makeKeyRecovery({ repoRoot, hostBridgeRoot: hostRoot, recoveryPublicKeyPath });
  const material = await keyRecovery.recoverMaterial({ checkpointId: inventory.checkpointId,
    envelopePath: canonicalEnvelope, envelopeSha256: inventory.recoveryEnvelopeSha256 });
  let verificationRoot;
  try {
    if (!material || !Buffer.isBuffer(material.bundleKey) || material.bundleKey.length !== 32 ||
        !material.runtimeSecrets || typeof material.runtimeSecrets !== 'object') fail('scheduler_recovery_material_invalid');
    const restoreRoot = resolve(providerOptions.restoreRoot);
    await assertSafePathPrefix(restoreRoot);
    await mkdir(restoreRoot, { recursive: true, mode: 0o700 });
    const canonicalRestoreRoot = await assertSafePathPrefix(restoreRoot);
    verificationRoot = resolve(canonicalRestoreRoot, `.verify-${checkpointHex}-${randomUUID().replaceAll('-', '')}`);
    const sealed = inventory.files[0];
    const opened = await openSealedCheckpointPayload({ encryptedPath: resolve(bundleRoot, sealed.path),
      expectedEncryptedSha256: sealed.sha256, expectedEncryptedBytes: sealed.bytes, bundleRoot,
      destinationRoot: verificationRoot, checkpointId: inventory.checkpointId,
      externalKeyRecoveryPath: canonicalEnvelope, recoverKey: async () => material.bundleKey });
    if (opened.status !== 'authenticated' || opened.payloadManifestSha256 !== inventory.payloadManifestSha256) {
      fail('scheduler_payload_manifest_invalid');
    }
    const readJson = async (relativePath, expectedKind = 'evidence') => {
      const row = opened.manifest.files.find((file) => file.path === relativePath && file.kind === expectedKind);
      if (!row) fail('scheduler_evidence_missing');
      const bytes = await readFile(resolve(verificationRoot, ...relativePath.split('/')));
      let value;
      try { value = JSON.parse(bytes.toString('utf8')); }
      catch { fail('scheduler_evidence_invalid'); }
      return { value, bytes };
    };
    const [beforeFile, afterFile, reconciliationFile, officialFile, closureFile] = await Promise.all([
      readJson('evidence/source-before.json'), readJson('evidence/source-after.json'),
      readJson('evidence/reconciliation.json'), readJson('evidence/official-evidence-manifest.json'),
      readJson('operator/authoritative-closure.json', 'closure'),
    ]);
    const before = beforeFile.value;
    const after = afterFile.value;
    const reconciliation = reconciliationFile.value;
    const official = officialFile.value;
    const closure = closureFile.value;
    const source = inventory.checkpointSource;
    const officialSha256 = sha256(officialFile.bytes);
    const closureSourceHashes = new Set([
      sha256(Buffer.from(`${JSON.stringify(closure)}\n`)),
      sha256(Buffer.from(`${JSON.stringify(closure, null, 2)}\n`)),
    ]);
    if (!before || !after || !reconciliation || !official || !source ||
        before.sourceDatabase !== source.sourceDatabase || after.sourceDatabase !== source.sourceDatabase ||
        before.snapshotBoundary !== source.boundary || after.snapshotBoundary !== source.boundary ||
        before.snapshotBoundaryId !== source.snapshotBoundaryId || after.snapshotBoundaryId !== source.snapshotBoundaryId ||
        before.snapshotAt !== source.sourceSnapshotAt || after.snapshotAt !== source.sourceAfterSnapshotAt ||
        before.snapshotBoundary !== 'admission_frozen_database_quiescent' ||
        before.databaseTotalsSha256 !== inventory.databaseTotalsSha256 || after.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        before.sourceBuildSha256 !== inventory.sourceBuildSha256 || after.sourceBuildSha256 !== inventory.sourceBuildSha256 ||
        canonical(before.operationBindings) !== canonical(inventory.operationBindings) ||
        canonical(after.operationBindings) !== canonical(inventory.operationBindings) ||
        canonical(before.reportDeletionReceipts) !== canonical(inventory.reportDeletionReceipts) ||
        canonical(after.reportDeletionReceipts) !== canonical(inventory.reportDeletionReceipts) ||
        reconciliation.schemaVersion !== 'beta-combined-checkpoint-reconciliation/v1' ||
        reconciliation.sourceStable !== true || reconciliation.snapshotBoundaryId !== source.snapshotBoundaryId ||
        reconciliation.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        reconciliation.sourceBuildSha256 !== inventory.sourceBuildSha256 ||
        canonical(reconciliation.operationBindings) !== canonical(inventory.operationBindings) ||
        reconciliation.officialEvidenceManifestSha256 !== officialSha256 ||
        !closureSourceHashes.has(reconciliation.authoritativeClosureSha256) ||
        closure.schemaVersion !== 'beta-report-closure-state/v1' || closure.betaEndedAt !== inventory.betaEndedAt ||
        !HASH.test(closure.sourceEvidenceSha256 ?? '') || official.schemaVersion !== 'beta-official-evidence-source/v1' ||
        typeof official.sourceProfile !== 'string' || !official.sourceProfile ||
        official.sourceBuildSha256 !== inventory.sourceBuildSha256 || !Array.isArray(official.runIds) ||
        official.runIds.length < 1 || !Array.isArray(official.files) || official.files.length < 1 ||
        !source.officialEvidenceSource || source.officialEvidenceSource.profile !== official.sourceProfile ||
        source.officialEvidenceSource.runIdCount !== official.runIds.length ||
        source.officialEvidenceSource.runIdsSha256 !== sha256(Buffer.from(canonical(official.runIds))) ||
        inventory.payloadSummary.officialEvidenceFileCount !== official.files.length ||
        inventory.payloadSummary.reportCount !== before.reportCount || inventory.payloadSummary.uploadCount !== before.uploadCount ||
        inventory.payloadSummary.screenshotCount !== before.imageFiles?.length) fail('scheduler_official_source_evidence_invalid');
    for (const file of official.files) {
      if (!file || typeof file.path !== 'string' || !file.path.startsWith('evidence/official/') ||
          !Number.isSafeInteger(file.bytes) || !HASH.test(file.sha256 ?? '') ||
          typeof file.role !== 'string' || !/^[a-z][a-z0-9_-]{1,63}$/.test(file.role)) fail('scheduler_official_evidence_file_invalid');
      const observed = await inspectBackupFile(verificationRoot, file.path, 'evidence');
      if (observed.bytes !== file.bytes || observed.sha256 !== file.sha256) fail('scheduler_official_evidence_file_mismatch');
    }
    return { status: 'verified', sourceStable: true, sha256: officialSha256 };
  } finally {
    if (Buffer.isBuffer(material?.bundleKey)) material.bundleKey.fill(0);
    for (const key of Object.keys(material?.runtimeSecrets ?? {})) material.runtimeSecrets[key] = '';
    if (verificationRoot) await rm(verificationRoot, { recursive: true, force: true });
  }
}

/**
 * AICODE-NOTE: This entry uses process-owned freeze/restart callbacks; it does not install a host timer or choose a target OS.
 * Concrete local scheduler entry: daily and pre-migration runs both invoke the sealed checkpoint provider.
 * The caller owns process supervision (stopApi/restartApi); target-host timer installation remains separate.
 */
export async function runLocalCombinedBackupSchedule(providerOptions, { requestedKind = 'daily' } = {}) {
  if (!providerOptions || typeof providerOptions !== 'object' || !isAbsolute(providerOptions.repoRoot ?? '') ||
      !isAbsolute(providerOptions.backupRoot ?? '') || !isAbsolute(providerOptions.restoreRoot ?? '') ||
      !isAbsolute(providerOptions.privateDataDir ?? '') || !isAbsolute(providerOptions.closureStatePath ?? '') ||
      !isAbsolute(providerOptions.officialEvidenceRoot ?? providerOptions.repoRoot) ||
      typeof providerOptions.databaseUrl !== 'string' || typeof providerOptions.observerDatabaseUrl !== 'string' ||
      !HASH.test(providerOptions.sourceBuildSha256 ?? '') ||
      !(typeof providerOptions.officialEvidenceRefs === 'function' ||
        (providerOptions.officialEvidenceRefs && typeof providerOptions.officialEvidenceRefs === 'object')) ||
      typeof providerOptions.stopApi !== 'function' || typeof providerOptions.restartApi !== 'function' ||
      typeof providerOptions.getRuntimeRecoverySecrets !== 'function' ||
      ['hostBridgeRoot', 'hostOperatorRoot', 'recoveryPublicKeyPath', 'recoveryPrivateKeyPath'].some((name) =>
        providerOptions[name] !== undefined && !isAbsolute(providerOptions[name])) ||
      providerOptions.checkpointBundleRoot !== undefined || providerOptions.checkpointId !== undefined) fail('scheduler_provider_options_invalid');
  const databaseName = sourceDbName(providerOptions.databaseUrl);
  if (sourceDbName(providerOptions.observerDatabaseUrl) !== databaseName) fail('observer_database_target_mismatch');
  const closure = await readAuthoritativeClosure(providerOptions.closureStatePath);
  const Pool = createPg(resolve(providerOptions.repoRoot));
  const now = await readDatabaseClock({ Pool, databaseUrl: withDatabase(providerOptions.observerDatabaseUrl, databaseName), databaseName });
  const backupRoot = resolve(providerOptions.backupRoot);
  const externalEnvelope = (checkpointId) => resolve(backupRoot, 'recovery', `${checkpointId.replaceAll('-', '')}.envelope.json`);
  const discardCurrentEnvelope = async (checkpointId) => {
    const path = externalEnvelope(checkpointId);
    let info;
    try { info = await lstat(path); } catch (error) { if (error?.code === 'ENOENT') return; throw error; }
    if (info.isSymbolicLink() || !info.isFile()) fail('scheduler_recovery_envelope_path_invalid');
    await rm(path, { force: false });
  };
  return runDailyBackupScheduler({ backupRoot, now, authoritativeBetaEndedAt: closure.betaEndedAt, requestedKind,
    executeCheckpoint: async ({ checkpointId, checkpointDirectory, kind, capturedAt }) => {
      let provider;
      try {
        provider = await createLocalCombinedBackup({ ...providerOptions, checkpointId, kind,
          checkpointBundleRoot: checkpointDirectory });
        const created = await provider.createCheckpoint({ now: capturedAt });
        if (!created || created.status !== 'checkpoint_verified' || created.checkpointId !== checkpointId ||
            created.inventory?.checkpointId !== checkpointId || created.inventory.kind !== kind ||
            created.bundleRoot !== checkpointDirectory || created.writesMayBeEnabled !== false) fail('scheduler_provider_checkpoint_unverified');
        validateBackupInventory(created.inventory);
        return created;
      } catch (error) {
        await discardCurrentEnvelope(checkpointId);
        throw error;
      }
    },
    verifyOfficialSource: async ({ checkpointDirectory, inventory }) => {
      try { return await verifyLocalCheckpointOfficialSource({ providerOptions, checkpointDirectory, inventory }); }
      catch (error) {
        const name = resolve(checkpointDirectory).slice(backupRoot.length + 1);
        if (name === `.pending-${inventory?.checkpointId?.replaceAll('-', '')}`) {
          await discardCurrentEnvelope(inventory.checkpointId);
        }
        throw error;
      }
    },
  });
}
