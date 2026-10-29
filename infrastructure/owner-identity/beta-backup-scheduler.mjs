import { createHash, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { lstat, mkdir, open, readFile, readdir, realpath, rename, rm, unlink, writeFile, link } from 'node:fs/promises';
import { dirname, isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { planBackupRotation, validateBackupInventory, verifyBackupFiles, verifyBackupIntegrity } from './beta-backup-inventory.mjs';

const DAY_MS = 86_400_000;
const HASH = /^[0-9a-f]{64}$/;
const UUID_HEX = /^[a-f0-9]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROOT_MARKER = '.beta-backup-root.json';
const SCHEDULE_FILE = '.beta-backup-schedule.json';

function fail(code) { throw new Error(`beta_backup_schedule_${code}`); }
function hash(value) { return createHash('sha256').update(value).digest('hex'); }
function canonical(value) { return JSON.stringify(value); }
function within(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`));
}
function isoTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) fail('invalid_time');
  return Date.parse(value);
}

async function noSymlinkPath(path, expectedType) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  const parts = relative(root, absolute).split(sep).filter(Boolean);
  let finalInfo;
  for (let i = 0; i < parts.length; i += 1) {
    current = resolve(current, parts[i]);
    const info = await lstat(current).catch(() => fail('path_missing'));
    if (info.isSymbolicLink()) fail('path_symlink');
    if (i < parts.length - 1 && !info.isDirectory()) fail('path_parent_not_directory');
    if (i === parts.length - 1) finalInfo = info;
  }
  if (!finalInfo || (expectedType === 'directory' ? !finalInfo.isDirectory() : !finalInfo.isFile())) fail('path_type_invalid');
  return realpath(absolute);
}

async function writeNewJson(path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let handle;
  let created = false;
  try {
    handle = await open(path, 'wx', 0o600);
    created = true;
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    if (created) await unlink(path).catch(() => undefined);
    if (error?.code === 'EEXIST') throw error;
    fail('journal_write_failed');
  }
  return hash(bytes);
}

async function writeScheduleState(path, value) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    const directory = await open(dirname(path), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    fail('schedule_state_write_failed');
  }
}

function schedulerOwnerAlive(owner) {
  if (!owner || owner.schemaVersion !== 'beta-backup-scheduler-lock/v1' ||
      owner.host !== hostname() || !Number.isSafeInteger(owner.pid) || owner.pid < 1 ||
      !UUID.test(owner.instanceId ?? '') || !Number.isFinite(Date.parse(owner.startedAt ?? ''))) {
    fail('scheduler_lock_owner_unverifiable');
  }
  try {
    process.kill(owner.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    // EPERM means the same-host process exists but cannot be signaled by this user.
    if (error?.code === 'EPERM') return true;
    fail('scheduler_lock_process_probe_failed');
  }
}

async function readLockOwner(lockPath) {
  let info;
  try { info = await lstat(lockPath); } catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  if (info.isSymbolicLink() || !info.isFile()) fail('scheduler_lock_path_invalid');
  let owner;
  try { owner = JSON.parse(await readFile(lockPath, 'utf8')); } catch { fail('scheduler_lock_owner_unverifiable'); }
  if (!owner || owner.schemaVersion !== 'beta-backup-scheduler-lock/v1' || owner.host !== hostname() ||
      !Number.isSafeInteger(owner.pid) || owner.pid < 1 || !UUID.test(owner.instanceId ?? '') ||
      typeof owner.startedAt !== 'string' || !Number.isFinite(Date.parse(owner.startedAt))) fail('scheduler_lock_owner_unverifiable');
  return owner;
}

async function readRetirementJson(path) {
  const info = await lstat(path).catch((error) => { if (error?.code === 'ENOENT') return null; throw error; });
  if (!info) return null;
  if (info.isSymbolicLink() || !info.isFile()) fail('retirement_journal_path_invalid');
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { fail('retirement_journal_invalid'); }
}

/**
 * Publish a fully written owner lease atomically. A crash cannot leave the old empty marker
 * produced by open(wx) before JSON was written. A dead same-host PID can be reclaimed; age alone
 * never permits breaking an active scheduler lease.
 */
async function acquireSchedulerLock(root) {
  const lockPath = resolve(root, '.scheduler.lock');
  const instanceId = randomUUID();
  const owner = { schemaVersion: 'beta-backup-scheduler-lock/v1', pid: process.pid,
    host: hostname(), instanceId, startedAt: new Date().toISOString() };
  const preparedPath = resolve(root, `.scheduler-lock-owner-${process.pid}-${instanceId}.json`);
  await writeNewJson(preparedPath, owner);
  try {
    try {
      await link(preparedPath, lockPath);
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const current = await readLockOwner(lockPath);
      if (!current) fail('scheduler_lock_raced');
      if (schedulerOwnerAlive(current)) fail('scheduler_lock_held');
      // Re-read immediately before unlink so a changed lease is never removed based on stale data.
      const confirmed = await readLockOwner(lockPath);
      if (!confirmed || confirmed.instanceId !== current.instanceId || confirmed.pid !== current.pid ||
          schedulerOwnerAlive(confirmed)) fail('scheduler_lock_raced');
      await unlink(lockPath);
      try { await link(preparedPath, lockPath); }
      catch (retryError) { if (retryError?.code === 'EEXIST') fail('scheduler_lock_held'); throw retryError; }
    }
    await unlink(preparedPath);
    const release = async () => {
      const current = await readLockOwner(lockPath);
      if (current?.instanceId === instanceId && current.pid === process.pid) await unlink(lockPath);
    };
    return { owner, release };
  } catch (error) {
    await unlink(preparedPath).catch(() => undefined);
    throw error;
  }
}

async function readInventory(directory, checkpointId) {
  const inventoryPath = resolve(directory, 'inventory.json');
  await noSymlinkPath(inventoryPath, 'file');
  let inventory;
  try { inventory = JSON.parse(await readFile(inventoryPath, 'utf8')); } catch { fail('checkpoint_inventory_invalid'); }
  validateBackupInventory(inventory);
  if (inventory.checkpointId !== checkpointId) fail('checkpoint_directory_identity_mismatch');
  return { inventory, inventoryPath, inventorySha256: hash(await readFile(inventoryPath)) };
}

async function listCheckpointDirectories(backupRoot) {
  const entries = await readdir(backupRoot, { withFileTypes: true });
  const output = [];
  for (const entry of entries) {
    if (!UUID_HEX.test(entry.name)) continue;
    const directory = resolve(backupRoot, entry.name);
    if (!entry.isDirectory() || entry.isSymbolicLink()) fail('checkpoint_directory_unsafe');
    const canonicalDirectory = await noSymlinkPath(directory, 'directory');
    if (!within(backupRoot, canonicalDirectory) || canonicalDirectory === backupRoot) fail('checkpoint_directory_escape');
    const checkpointId = `${entry.name.slice(0, 8)}-${entry.name.slice(8, 12)}-${entry.name.slice(12, 16)}-${entry.name.slice(16, 20)}-${entry.name.slice(20)}`;
    output.push({ checkpointId, directory: canonicalDirectory, ...(await readInventory(canonicalDirectory, checkpointId)) });
  }
  return output;
}

async function assertNoSymlinkTree(root, relativePath = '') {
  for (const entry of await readdir(resolve(root, relativePath), { withFileTypes: true })) {
    const childRelative = relativePath ? `${relativePath}/${entry.name}` : entry.name;
    const child = resolve(root, childRelative);
    const info = await lstat(child);
    if (info.isSymbolicLink()) fail('retirement_tree_symlink');
    if (info.isDirectory()) await assertNoSymlinkTree(root, childRelative);
    else if (!info.isFile()) fail('retirement_tree_special_file');
  }
}

async function finishRetirement({ backupRoot, checkpointId, started, completePath, recoveredAfterCrash = false }) {
  const target = resolve(backupRoot, checkpointId.replaceAll('-', ''));
  let info;
  try { info = await lstat(target); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  if (info) {
    if (info.isSymbolicLink() || !info.isDirectory()) fail('retirement_target_invalid');
    const canonicalTarget = await noSymlinkPath(target, 'directory');
    if (!within(backupRoot, canonicalTarget) || canonicalTarget === backupRoot) fail('retirement_target_escape');
    await assertNoSymlinkTree(canonicalTarget);
    // The started journal is written only after the full inventory passes byte verification.
    // If a crash interrupted recursive deletion, finish the already-authorized retirement.
    await rm(canonicalTarget, { recursive: true, force: false, maxRetries: 2, retryDelay: 100 });
  }
  const remaining = await lstat(target).catch((error) => { if (error?.code === 'ENOENT') return null; throw error; });
  if (remaining) fail('retirement_target_remains');
  const complete = { ...started, status: 'retired', completedAt: new Date().toISOString(), recoveredAfterCrash };
  try { await writeNewJson(completePath, complete); }
  catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const existing = await readRetirementJson(completePath);
    if (existing.checkpointId !== checkpointId || existing.inventorySha256 !== started.inventorySha256 ||
        existing.retirementProofSha256 !== started.retirementProofSha256 || existing.status !== 'retired') fail('retirement_journal_conflict');
  }
  return checkpointId;
}

async function retireCheckpoint({ backupRoot, checkpoint, integrityProof }) {
  const journalRoot = resolve(backupRoot, 'retirement-journal');
  await mkdir(journalRoot, { recursive: true, mode: 0o700 });
  await noSymlinkPath(journalRoot, 'directory');
  const startedPath = resolve(journalRoot, `${checkpoint.checkpointId}.started.json`);
  const completePath = resolve(journalRoot, `${checkpoint.checkpointId}.complete.json`);
  const started = { schemaVersion: 'beta-backup-retirement/v1', checkpointId: checkpoint.checkpointId,
    inventorySha256: checkpoint.inventorySha256, retirementProofSha256: integrityProof,
    startedAt: new Date().toISOString(), status: 'retirement_started' };
  try { await writeNewJson(startedPath, started); }
  catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const existing = await readRetirementJson(startedPath);
    if (!existing) fail('retirement_journal_conflict');
    if (existing.inventorySha256 !== checkpoint.inventorySha256 || existing.checkpointId !== checkpoint.checkpointId ||
        existing.retirementProofSha256 !== integrityProof || existing.status !== 'retirement_started') fail('retirement_journal_conflict');
  }
  const existingComplete = await readRetirementJson(completePath);
  if (existingComplete) {
    if (existingComplete.checkpointId !== checkpoint.checkpointId || existingComplete.inventorySha256 !== checkpoint.inventorySha256 ||
        existingComplete.retirementProofSha256 !== integrityProof || existingComplete.status !== 'retired') fail('retirement_journal_conflict');
    const targetExists = await lstat(resolve(backupRoot, checkpoint.checkpointId.replaceAll('-', ''))).then(() => true)
      .catch((error) => { if (error?.code === 'ENOENT') return false; throw error; });
    if (targetExists) fail('retirement_completed_checkpoint_present');
    return checkpoint.checkpointId;
  }
  return finishRetirement({ backupRoot, checkpointId: checkpoint.checkpointId, started, completePath });
}

async function reconcileRetirementJournal(backupRoot) {
  const journalRoot = resolve(backupRoot, 'retirement-journal');
  let entries;
  try { entries = await readdir(journalRoot, { withFileTypes: true }); }
  catch (error) { if (error?.code === 'ENOENT') return []; throw error; }
  await noSymlinkPath(journalRoot, 'directory');
  const recovered = [];
  for (const entry of entries) {
    if (!entry.name.endsWith('.started.json')) continue;
    if (!entry.isFile() || entry.isSymbolicLink()) fail('retirement_journal_path_invalid');
    const journalStem = entry.name.slice(0, -'.started.json'.length);
    let checkpointId;
    if (UUID_HEX.test(journalStem)) {
      checkpointId = `${journalStem.slice(0, 8)}-${journalStem.slice(8, 12)}-${journalStem.slice(12, 16)}-${journalStem.slice(16, 20)}-${journalStem.slice(20)}`;
    } else if (UUID.test(journalStem)) {
      checkpointId = journalStem;
    } else {
      fail('retirement_journal_identity_invalid');
    }
    const checkpointHex = checkpointId.replaceAll('-', '');
    const startedPath = resolve(journalRoot, entry.name);
    await noSymlinkPath(startedPath, 'file');
    let started;
    try { started = JSON.parse(await readFile(startedPath, 'utf8')); } catch { fail('retirement_journal_invalid'); }
    if (started.schemaVersion !== 'beta-backup-retirement/v1' || started.checkpointId !== checkpointId ||
        !HASH.test(started.inventorySha256 ?? '') || !HASH.test(started.retirementProofSha256 ?? '') ||
        started.status !== 'retirement_started' || !Number.isFinite(Date.parse(started.startedAt ?? ''))) fail('retirement_journal_invalid');
    const completePath = resolve(journalRoot, `${journalStem}.complete.json`);
    const existingComplete = await readRetirementJson(completePath);
    const target = resolve(backupRoot, checkpointHex);
    if (existingComplete) {
      if (existingComplete.schemaVersion !== 'beta-backup-retirement/v1' || existingComplete.checkpointId !== checkpointId ||
          existingComplete.inventorySha256 !== started.inventorySha256 || existingComplete.retirementProofSha256 !== started.retirementProofSha256 ||
          existingComplete.status !== 'retired') fail('retirement_journal_conflict');
      const exists = await lstat(target).then(() => true).catch((error) => { if (error?.code === 'ENOENT') return false; throw error; });
      if (exists) fail('retirement_completed_checkpoint_present');
      continue;
    }
    const info = await lstat(target).catch((error) => { if (error?.code === 'ENOENT') return null; throw error; });
    if (info && (info.isSymbolicLink() || !info.isDirectory())) fail('retirement_target_invalid');
    recovered.push(await finishRetirement({ backupRoot, checkpointId, started, completePath, recoveredAfterCrash: true }));
  }
  return recovered;
}

async function reconcilePendingCaptures({ backupRoot, verifyOfficialSource, now, authoritativeBetaEndedAt }) {
  const entries = await readdir(backupRoot, { withFileTypes: true });
  const markers = entries.filter((entry) => /^\.pending-[a-f0-9]{32}\.owner\.json$/.test(entry.name));
  const recoveredCheckpointIds = [];
  for (const entry of markers) {
    if (!entry.isFile() || entry.isSymbolicLink()) fail('pending_capture_marker_unsafe');
    const markerPath = resolve(backupRoot, entry.name);
    await noSymlinkPath(markerPath, 'file');
    let marker;
    try { marker = JSON.parse(await readFile(markerPath, 'utf8')); } catch { fail('pending_capture_marker_invalid'); }
    const checkpointHex = entry.name.slice('.pending-'.length, -'.owner.json'.length);
    const checkpointId = `${checkpointHex.slice(0, 8)}-${checkpointHex.slice(8, 12)}-${checkpointHex.slice(12, 16)}-${checkpointHex.slice(16, 20)}-${checkpointHex.slice(20)}`;
    if (marker.schemaVersion !== 'beta-backup-pending-capture/v1' || marker.checkpointId !== checkpointId ||
        !['daily', 'pre_migration', 'retention_sanitized'].includes(marker.kind) ||
        !UUID.test(marker.sourceRootId ?? '') || !Number.isFinite(Date.parse(marker.startedAt ?? '')) || !marker.owner ||
        marker.owner.schemaVersion !== 'beta-backup-scheduler-lock/v1') fail('pending_capture_marker_invalid');
    if (schedulerOwnerAlive(marker.owner)) fail('pending_capture_owner_alive');

    const staging = resolve(backupRoot, `.pending-${checkpointHex}`);
    const target = resolve(backupRoot, checkpointHex);
    const stageInfo = await lstat(staging).catch((error) => { if (error?.code === 'ENOENT') return null; throw error; });
    const targetInfo = await lstat(target).catch((error) => { if (error?.code === 'ENOENT') return null; throw error; });
    if ((stageInfo && (stageInfo.isSymbolicLink() || !stageInfo.isDirectory())) ||
        (targetInfo && (targetInfo.isSymbolicLink() || !targetInfo.isDirectory()))) fail('pending_capture_directory_invalid');
    if (stageInfo && targetInfo) fail('pending_capture_both_stage_and_published_exist');

    const candidate = targetInfo ? target : staging;
    let inventoryExists = false;
    if (candidate !== target) {
      inventoryExists = await lstat(resolve(candidate, 'inventory.json')).then(() => true)
        .catch((error) => { if (error?.code === 'ENOENT') return false; throw error; });
    } else inventoryExists = true;
    if (!inventoryExists) {
      if (stageInfo) {
        await noSymlinkPath(staging, 'directory');
        await assertNoSymlinkTree(staging);
        await rm(staging, { recursive: true, force: false, maxRetries: 2, retryDelay: 100 });
      }
      await unlink(markerPath);
      if (marker.kind === 'pre_migration') fail('pre_migration_capture_interrupted');
      continue;
    }

    let checkpoint;
    try { checkpoint = await readInventory(candidate, checkpointId); } catch {
      if (stageInfo) {
        await noSymlinkPath(staging, 'directory');
        await assertNoSymlinkTree(staging);
        await rm(staging, { recursive: true, force: false, maxRetries: 2, retryDelay: 100 });
        await unlink(markerPath);
      }
      fail(marker.kind === 'pre_migration' ? 'pre_migration_checkpoint_invalid' : 'pending_checkpoint_invalid');
    }
    const retention = await verifyBackupFiles(candidate, checkpoint.inventory, { now, authoritativeBetaEndedAt });
    if (retention.integrity !== 'passed' || retention.writesMayBeEnabled !== false) fail('pending_checkpoint_integrity_invalid');
    const official = await verifyOfficialSource({ checkpointDirectory: candidate, inventory: checkpoint.inventory });
    if (!official || official.status !== 'verified' || official.sourceStable !== true || !HASH.test(official.sha256 ?? '')) {
      fail('pending_checkpoint_official_source_unverified');
    }
    if (stageInfo) await rename(staging, target);
    await unlink(markerPath);
    recoveredCheckpointIds.push(checkpointId);
  }

  // Markerless pending directories have no owner proof and are retained for operator review.
  for (const entry of entries) {
    if (!/^\.pending-[a-f0-9]{32}$/.test(entry.name)) continue;
    const hex = entry.name.slice('.pending-'.length);
    if (!markers.some((marker) => marker.name === `.pending-${hex}.owner.json`)) fail('pending_capture_owner_unverifiable');
  }
  return recoveredCheckpointIds;
}

/** Create an empty, dedicated same-host backup root. Existing directories are never adopted implicitly. */
export async function initializeBackupRoot(backupRoot) {
  if (!isAbsolute(backupRoot ?? '')) fail('backup_root_must_be_absolute');
  const absolute = resolve(backupRoot);
  await mkdir(absolute, { recursive: false, mode: 0o700 });
  const canonicalRoot = await noSymlinkPath(absolute, 'directory');
  const marker = { schemaVersion: 'beta-backup-root/v1', rootId: randomUUID(), failureDomain: 'same_host', createdAt: new Date().toISOString() };
  await writeNewJson(resolve(canonicalRoot, ROOT_MARKER), marker);
  return marker;
}

/** One daily scheduler tick: run and verify the new checkpoint before pruning verified older copies. */
export async function runDailyBackupScheduler({ backupRoot, now = new Date().toISOString(), authoritativeBetaEndedAt = null,
  requestedKind = 'daily', executeCheckpoint, verifyOfficialSource }) {
  if (!isAbsolute(backupRoot ?? '') || typeof executeCheckpoint !== 'function' || typeof verifyOfficialSource !== 'function') {
    fail('scheduler_input_invalid');
  }
  const nowMs = isoTime(now);
  if (!(authoritativeBetaEndedAt === null || (typeof authoritativeBetaEndedAt === 'string' && isoTime(authoritativeBetaEndedAt)))) {
    fail('authoritative_closure_time_invalid');
  }
  if (!['daily', 'pre_migration'].includes(requestedKind)) fail('requested_kind_invalid');
  const canonicalRoot = await noSymlinkPath(backupRoot, 'directory');
  const markerPath = resolve(canonicalRoot, ROOT_MARKER);
  await noSymlinkPath(markerPath, 'file');
  const marker = JSON.parse(await readFile(markerPath, 'utf8'));
  if (marker.schemaVersion !== 'beta-backup-root/v1' || marker.failureDomain !== 'same_host' || !UUID.test(marker.rootId ?? '')) fail('backup_root_marker_invalid');
  const schedulerLease = await acquireSchedulerLock(canonicalRoot);
  try {
    const recoveredPendingCheckpointIds = await reconcilePendingCaptures({ backupRoot: canonicalRoot,
      verifyOfficialSource, now, authoritativeBetaEndedAt });
    const reconciledRetiredCheckpointIds = await reconcileRetirementJournal(canonicalRoot);
    const statePath = resolve(canonicalRoot, SCHEDULE_FILE);
    let prior = null;
    try {
      await noSymlinkPath(statePath, 'file');
      prior = JSON.parse(await readFile(statePath, 'utf8'));
      if (prior.schemaVersion !== 'beta-backup-schedule-state/v1' || !validScheduleState(prior)) fail('schedule_state_invalid');
    } catch (error) {
      if (!String(error?.message ?? '').includes('path_missing')) throw error;
    }
    if (requestedKind === 'daily' && prior?.lastSuccessfulAt && nowMs < isoTime(prior.lastSuccessfulAt) + DAY_MS) {
      return { status: 'not_due', nextDueAt: new Date(isoTime(prior.lastSuccessfulAt) + DAY_MS).toISOString(), writesMayBeEnabled: false };
    }
    const retentionExpired = authoritativeBetaEndedAt !== null && nowMs >= isoTime(authoritativeBetaEndedAt) + 30 * DAY_MS;
    const kind = requestedKind === 'pre_migration' ? 'pre_migration' : retentionExpired ? 'retention_sanitized' : 'daily';
    const checkpointId = randomUUID();
    const checkpointHex = checkpointId.replaceAll('-', '');
    const stagingDirectory = resolve(canonicalRoot, `.pending-${checkpointHex}`);
    const checkpointDirectory = resolve(canonicalRoot, checkpointHex);
    const pendingMarkerPath = resolve(canonicalRoot, `.pending-${checkpointHex}.owner.json`);
    await writeNewJson(pendingMarkerPath, { schemaVersion: 'beta-backup-pending-capture/v1', checkpointId, kind,
      sourceRootId: marker.rootId, startedAt: new Date().toISOString(), owner: schedulerLease.owner });
    let stagingCreated = false;
    let published = false;
    let created;
    let inventoryFile;
    let officialSource;
    try {
      await mkdir(stagingDirectory, { recursive: false, mode: 0o700 });
      stagingCreated = true;
      created = await executeCheckpoint({ checkpointId, checkpointDirectory: stagingDirectory, kind, capturedAt: now,
        authoritativeBetaEndedAt, sourceRootId: marker.rootId });
      if (!created || created.status !== 'checkpoint_verified' || created.checkpointId !== checkpointId ||
          created.inventory?.checkpointId !== checkpointId || created.inventory.kind !== kind || created.writesMayBeEnabled !== false) {
        fail('checkpoint_creation_not_verified');
      }
      validateBackupInventory(created.inventory);
      inventoryFile = await readInventory(stagingDirectory, checkpointId);
      if (canonical(inventoryFile.inventory) !== canonical(created.inventory)) fail('checkpoint_inventory_output_mismatch');
      officialSource = await verifyOfficialSource({ checkpointDirectory: stagingDirectory, inventory: inventoryFile.inventory });
      if (!officialSource || officialSource.status !== 'verified' || officialSource.sourceStable !== true ||
          !HASH.test(officialSource.sha256 ?? '')) fail('official_source_verification_failed');
      await rename(stagingDirectory, checkpointDirectory);
      published = true;
      await unlink(pendingMarkerPath);
    } catch (error) {
      if (stagingCreated && !published) {
        try {
          await noSymlinkPath(stagingDirectory, 'directory');
          await assertNoSymlinkTree(stagingDirectory);
          await rm(stagingDirectory, { recursive: true, force: false, maxRetries: 2, retryDelay: 100 });
          await unlink(pendingMarkerPath).catch(() => undefined);
        } catch { fail('pending_capture_cleanup_failed'); }
      }
      throw error;
    }

    const existing = await listCheckpointDirectories(canonicalRoot);
    const plan = planBackupRotation(existing.map((item) => item.inventory), { now, authoritativeBetaEndedAt });
    if (!plan.keep.includes(checkpointId)) fail('new_checkpoint_not_retained');
    const keepIds = new Set(plan.keep);
    for (const item of existing) {
      if (!keepIds.has(item.checkpointId)) continue;
      const verified = await verifyBackupFiles(item.directory, item.inventory, { now, authoritativeBetaEndedAt });
      if (verified.integrity !== 'passed' || verified.writesMayBeEnabled !== false) fail('retained_checkpoint_integrity_failed');
    }
    const retireIds = new Set(plan.retire);
    const retiredCheckpointIds = [...reconciledRetiredCheckpointIds];
    for (const item of existing) {
      if (!retireIds.has(item.checkpointId)) continue;
      const integrity = await verifyBackupIntegrity(item.directory, item.inventory);
      if (integrity.integrity !== 'passed' || integrity.writesMayBeEnabled !== false) fail('retiring_checkpoint_integrity_failed');
      const integrityProof = hash(canonical({ inventorySha256: item.inventorySha256,
        fileCount: integrity.fileCount, integrity: integrity.integrity }));
      retiredCheckpointIds.push(await retireCheckpoint({ backupRoot: canonicalRoot, checkpoint: item, integrityProof }));
    }
    const scheduleState = {
      schemaVersion: 'beta-backup-schedule-state/v1', lastSuccessfulAt: now, lastCheckpointId: checkpointId,
      lastCheckpointKind: kind, keepCheckpointIds: plan.keep, retiredCheckpointIds,
      recoveredPendingCheckpointIds, officialEvidenceSha256: officialSource.sha256,
    };
    await writeScheduleState(statePath, scheduleState);
    return { status: 'checkpoint_scheduled_and_rotated', checkpointId, kind, keepCheckpointIds: plan.keep,
      retiredCheckpointIds, recoveredPendingCheckpointIds, officialEvidenceSha256: officialSource.sha256, writesMayBeEnabled: false };
  } finally {
    await schedulerLease.release();
  }
}

function validScheduleState(value) {
  return typeof value.lastSuccessfulAt === 'string' && Number.isFinite(Date.parse(value.lastSuccessfulAt)) &&
    UUID.test(value.lastCheckpointId ?? '') && ['daily', 'pre_migration', 'retention_sanitized'].includes(value.lastCheckpointKind) &&
    Array.isArray(value.keepCheckpointIds) && value.keepCheckpointIds.every((id) => UUID.test(id)) &&
    Array.isArray(value.retiredCheckpointIds) && value.retiredCheckpointIds.every((id) => UUID.test(id)) &&
    (!Object.hasOwn(value, 'recoveredPendingCheckpointIds') ||
      (Array.isArray(value.recoveredPendingCheckpointIds) && value.recoveredPendingCheckpointIds.every((id) => UUID.test(id)))) &&
    HASH.test(value.officialEvidenceSha256 ?? '');
}
