import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { inspectBackupFile, validateBackupInventory, verifyBackupIntegrity } from './beta-backup-inventory.mjs';
import { openSealedCheckpointPayload } from './beta-backup-sealed-bundle.mjs';

const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REPORT_RETENTION_SECONDS = 2_592_000;
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
function bindingSnapshotHash(snapshot) { return canonical(snapshot.operationBindings); }

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
  const restoredMaterial = await keyRecovery.recoverMaterial({ checkpointId: inventory.checkpointId,
    envelopePath: externalEnvelope.canonicalPath, envelopeSha256: inventory.recoveryEnvelopeSha256 });
  if (!restoredMaterial || !Buffer.isBuffer(restoredMaterial.bundleKey) || restoredMaterial.bundleKey.length !== 32 ||
      !restoredMaterial.runtimeSecrets || typeof restoredMaterial.runtimeSecrets !== 'object') fail('external_recovery_material_invalid');

  const restoreDatabaseName = `oid_restore_${randomUUID().replaceAll('-', '')}`;
  if (!/^oid_restore_[a-f0-9]{32}$/.test(restoreDatabaseName)) fail('restore_database_name_invalid');
  const restoreParent = await inspectPathChain(restore.restoreRoot, 'directory').then((row) => row.canonicalPath);
  const restoreRoot = resolve(restoreParent, restoreDatabaseName);
  if (!within(restoreParent, restoreRoot)) fail('restore_root_escape');
  await mkdir(restoreRoot, { recursive: false, mode: 0o700 });
  const privateDataDir = resolve(restoreRoot, 'private-data');
  const operatorDir = resolve(restoreRoot, 'operator');
  const unsealedRoot = resolve(restoreRoot, 'unsealed');
  await mkdir(privateDataDir, { recursive: false, mode: 0o700 });
  await mkdir(operatorDir, { recursive: false, mode: 0o700 });
  const closureStatePath = resolve(operatorDir, 'authoritative-closure.json');
  const closureCopySha256 = await writeClosureCopy(closureStatePath, cloneClosure);
  const sealed = inventory.files[0];
  let payload;
  try {
    payload = await openSealedCheckpointPayload({ encryptedPath: resolve(bundleRoot, sealed.path),
      expectedEncryptedSha256: sealed.sha256, expectedEncryptedBytes: sealed.bytes, bundleRoot,
      destinationRoot: unsealedRoot, checkpointId: inventory.checkpointId,
      externalKeyRecoveryPath: externalEnvelope.canonicalPath, recoverKey: async () => restoredMaterial.bundleKey });
    const sourceBefore = await readJson(resolve(unsealedRoot, 'evidence/source-before.json'));
    const sourceAfter = await readJson(resolve(unsealedRoot, 'evidence/source-after.json'));
    const reconciliation = await readJson(resolve(unsealedRoot, 'evidence/reconciliation.json'));
    const originalIds = validateOriginalIds(sourceBefore);
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
    const creationReceipt = await adapters.createRestoreDatabase({ databaseName: restoreDatabaseName, checkpointId: inventory.checkpointId });
    if (!creationReceipt || creationReceipt.status !== 'complete' || creationReceipt.databaseName !== restoreDatabaseName ||
        creationReceipt.checkpointId !== inventory.checkpointId || !UUID.test(creationReceipt.creationJobId ?? '') ||
        creationReceipt.createdFresh !== true) fail('restore_database_creation_receipt_invalid');
    const dbRestore = await adapters.restoreDatabaseDump({ databaseName: restoreDatabaseName, dumpPath,
      dumpSha256: dumpRow.sha256, checkpointId: inventory.checkpointId, creationJobId: creationReceipt.creationJobId });
    if (!dbRestore || dbRestore.status !== 'restored' || dbRestore.databaseName !== restoreDatabaseName || dbRestore.dumpSha256 !== dumpRow.sha256) {
      fail('database_restore_not_verified');
    }
    const fileRestore = await adapters.restorePrivateFiles({ payloadRoot: unsealedRoot, privateDataDir, restoreRoot });
    const imageRows = payload.manifest.files.filter((row) => row.kind === 'screenshot').map(({ path, bytes, sha256 }) => ({
      path, bytes, sha256 })).sort((a, b) => a.path.localeCompare(b.path));
    if (!fileRestore || fileRestore.status !== 'restored' || fileRestore.fileCount !== imageRows.length) fail('private_files_restore_not_verified');
    const beforeRetention = validateObserverSnapshot(await adapters.observeReadOnly({ databaseName: restoreDatabaseName,
      privateDataDir, closureStatePath }), restoreDatabaseName);
    if (beforeRetention.databaseTotalsSha256 !== inventory.databaseTotalsSha256 ||
        canonical(beforeRetention.operationBindings) !== canonical(inventory.operationBindings) ||
        canonical(beforeRetention.imageFiles) !== canonical(imageRows)) fail('restored_database_or_images_mismatch');

    let afterRetention = beforeRetention;
    let cloneCleanup = { status: 'not_required', retentionExpired: false, sourceCheckpointId: inventory.checkpointId,
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
        payloadFileCount: payload.extractedFileCount },
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
    restoredMaterial.bundleKey.fill(0);
    for (const key of Object.keys(restoredMaterial.runtimeSecrets ?? {})) restoredMaterial.runtimeSecrets[key] = '';
    throw error;
  } finally {
    await rm(unsealedRoot, { recursive: true, force: true }).catch(() => undefined);
  }
}
