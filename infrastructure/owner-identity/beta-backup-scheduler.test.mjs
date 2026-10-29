import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initializeBackupRoot, runDailyBackupScheduler } from './beta-backup-scheduler.mjs';
import { inspectBackupFile } from './beta-backup-inventory.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

async function rootFixture(t) {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-scheduler-'));
  const backupRoot = join(parent, 'backups');
  await initializeBackupRoot(backupRoot);
  t.after(() => rm(parent, { recursive: true, force: true }));
  return backupRoot;
}

function deadPid() {
  for (let pid = 2_000_000_000; pid < 2_000_000_100; pid += 1) {
    try { process.kill(pid, 0); } catch (error) { if (error?.code === 'ESRCH') return pid; }
  }
  throw new Error('no_dead_pid_fixture');
}

test('scheduler restart reclaims a proven-dead same-host owner and completes a deleted checkpoint receipt', async (t) => {
  const backupRoot = await rootFixture(t);
  const checkpointId = '10000000-0000-4000-8000-000000000001';
  const checkpointHex = checkpointId.replaceAll('-', '');
  const inventoryBytes = jsonBytes({ checkpointId, fixture: 'retirement crash recovery' });
  const inventorySha256 = sha(inventoryBytes);
  const integritySha256 = sha(JSON.stringify({ inventorySha256, fileCount: 1, integrity: 'passed' }));
  const journal = join(backupRoot, 'retirement-journal');
  await mkdir(journal);
  await writeFile(join(journal, `${checkpointHex}.started.json`), jsonBytes({
    schemaVersion: 'beta-backup-retirement/v1', checkpointId, inventorySha256,
    retirementProofSha256: integritySha256, startedAt: '2026-10-28T12:00:00.000Z', status: 'retirement_started',
  }), { flag: 'wx' });
  await writeFile(join(backupRoot, '.scheduler.lock'), jsonBytes({
    schemaVersion: 'beta-backup-scheduler-lock/v1', pid: deadPid(), host: hostname(),
    instanceId: randomUUID(), startedAt: '2026-10-28T12:00:00.000Z',
  }), { flag: 'wx' });

  await assert.rejects(runDailyBackupScheduler({ backupRoot, now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => {
      const receipt = JSON.parse(await readFile(join(journal, `${checkpointHex}.complete.json`), 'utf8'));
      assert.equal(receipt.status, 'retired');
      assert.equal(receipt.recoveredAfterCrash, true);
      throw new Error('controlled_scheduler_restart_stop');
    }, verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'a'.repeat(64) }),
  }), /controlled_scheduler_restart_stop/);

  await assert.rejects(readFile(join(backupRoot, '.scheduler.lock')), { code: 'ENOENT' });
  const complete = JSON.parse(await readFile(join(journal, `${checkpointHex}.complete.json`), 'utf8'));
  assert.equal(complete.inventorySha256, inventorySha256);
  assert.equal(complete.retirementProofSha256, integritySha256);
  assert.equal(complete.recoveredAfterCrash, true);
});

test('scheduler does not reclaim a live same-host owner lease based on elapsed time', async (t) => {
  const backupRoot = await rootFixture(t);
  const lock = { schemaVersion: 'beta-backup-scheduler-lock/v1', pid: process.pid, host: hostname(),
    instanceId: randomUUID(), startedAt: '2020-01-01T00:00:00.000Z' };
  const path = join(backupRoot, '.scheduler.lock');
  await writeFile(path, jsonBytes(lock), { flag: 'wx' });
  await assert.rejects(runDailyBackupScheduler({ backupRoot, now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => { throw new Error('must_not_start'); },
    verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'a'.repeat(64) }),
  }), /beta_backup_schedule_scheduler_lock_held/);
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), lock);
});

test('markerless interrupted staging is retained and fails closed without an owner proof', async (t) => {
  const backupRoot = await rootFixture(t);
  const staging = join(backupRoot, '.pending-20000000000040008000000000000001');
  await mkdir(staging);
  await writeFile(join(staging, 'private-stage.bin'), 'synthetic managed staging');
  await assert.rejects(runDailyBackupScheduler({ backupRoot, now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => { throw new Error('must_not_start'); },
    verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'a'.repeat(64) }),
  }), /beta_backup_schedule_pending_capture_owner_unverifiable/);
  assert.equal(await readFile(join(staging, 'private-stage.bin'), 'utf8'), 'synthetic managed staging');
});

test('failed pre-migration capture removes its own staging and never advances schedule state', async (t) => {
  const backupRoot = await rootFixture(t);
  await assert.rejects(runDailyBackupScheduler({ backupRoot, requestedKind: 'pre_migration', now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => { throw new Error('controlled_pre_migration_failure'); },
    verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'a'.repeat(64) }),
  }), /controlled_pre_migration_failure/);
  const entries = await (await import('node:fs/promises')).readdir(backupRoot);
  assert.equal(entries.some((name) => /^\.pending-[a-f0-9]{32}(?:\.owner\.json)?$/.test(name)), false);
  await assert.rejects(readFile(join(backupRoot, '.beta-backup-schedule.json')), { code: 'ENOENT' });
});

test('complete pre-migration staging with dead-owner proof is reverified and published after restart', async (t) => {
  const backupRoot = await rootFixture(t);
  const checkpointId = '20000000-0000-4000-8000-000000000001';
  const hex = checkpointId.replaceAll('-', '');
  const staging = join(backupRoot, `.pending-${hex}`);
  await mkdir(staging);
  await writeFile(join(staging, 'database.dump'), 'synthetic dump bytes');
  const database = await inspectBackupFile(staging, 'database.dump', 'database');
  const inventory = { schemaVersion: 'beta-backup-inventory/v1', checkpointId, kind: 'pre_migration', failureDomain: 'same_host',
    sourceBuildSha256: 'a'.repeat(64), capturedAt: '2026-10-29T11:00:00.000Z', betaEndedAt: null,
    reconciliationEvidenceSha256: 'b'.repeat(64), databaseTotalsSha256: 'c'.repeat(64), files: [database], reportDeletionReceipts: [] };
  await writeFile(join(staging, 'inventory.json'), jsonBytes(inventory), { flag: 'wx' });
  const rootMarker = JSON.parse(await readFile(join(backupRoot, '.beta-backup-root.json'), 'utf8'));
  await writeFile(join(backupRoot, `.pending-${hex}.owner.json`), jsonBytes({
    schemaVersion: 'beta-backup-pending-capture/v1', checkpointId, kind: 'pre_migration', sourceRootId: rootMarker.rootId,
    startedAt: '2026-10-29T11:00:00.000Z', owner: { schemaVersion: 'beta-backup-scheduler-lock/v1',
      pid: deadPid(), host: hostname(), instanceId: randomUUID(), startedAt: '2026-10-29T11:00:00.000Z' },
  }), { flag: 'wx' });

  await assert.rejects(runDailyBackupScheduler({ backupRoot, now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => { throw new Error('controlled_restart_stop'); },
    verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'd'.repeat(64) }),
  }), /controlled_restart_stop/);
  assert.equal((await readFile(join(backupRoot, hex, 'inventory.json'), 'utf8')).includes(checkpointId), true);
  await assert.rejects(readFile(join(backupRoot, `.pending-${hex}.owner.json`)), { code: 'ENOENT' });
});

test('legacy empty lock is not removed without same-host process identity proof', async (t) => {
  const backupRoot = await rootFixture(t);
  const lockPath = join(backupRoot, '.scheduler.lock');
  await writeFile(lockPath, '', { flag: 'wx' });
  await assert.rejects(runDailyBackupScheduler({ backupRoot, now: '2026-10-29T12:00:00.000Z',
    executeCheckpoint: async () => { throw new Error('must_not_start'); },
    verifyOfficialSource: async () => ({ status: 'verified', sourceStable: true, sha256: 'a'.repeat(64) }),
  }), /beta_backup_schedule_scheduler_lock_owner_unverifiable/);
  assert.equal(await readFile(lockPath, 'utf8'), '');
});

test('operational scheduler catches up once and retains seven daily checkpoints plus the latest pre-migration copy', async (t) => {
  const backupRoot = await rootFixture(t);
  const now = new Date('2026-10-29T12:00:00.000Z');
  const nowIso = now.toISOString();
  const checkpointRows = [];
  const writeCheckpoint = async ({ checkpointId, checkpointDirectory, kind, capturedAt }) => {
    const body = Buffer.from(`synthetic operational scheduler checkpoint ${checkpointId}`);
    await writeFile(join(checkpointDirectory, 'database.dump'), body, { flag: 'wx', mode: 0o600 });
    const database = await inspectBackupFile(checkpointDirectory, 'database.dump', 'database');
    const inventory = { schemaVersion: 'beta-backup-inventory/v1', checkpointId, kind, failureDomain: 'same_host',
      sourceBuildSha256: 'a'.repeat(64), capturedAt, betaEndedAt: null,
      reconciliationEvidenceSha256: 'b'.repeat(64), databaseTotalsSha256: 'c'.repeat(64),
      files: [database], reportDeletionReceipts: [] };
    await writeFile(join(checkpointDirectory, 'inventory.json'), jsonBytes(inventory), { flag: 'wx', mode: 0o600 });
    checkpointRows.push({ checkpointId, kind, capturedAt });
    return { status: 'checkpoint_verified', checkpointId, inventory, writesMayBeEnabled: false };
  };
  const seed = async (kind, ageDays, id) => {
    const checkpointId = id;
    const directory = join(backupRoot, checkpointId.replaceAll('-', ''));
    await mkdir(directory);
    await writeCheckpoint({ checkpointId, checkpointDirectory: directory, kind,
      capturedAt: new Date(now.valueOf() - ageDays * 24 * 60 * 60 * 1000).toISOString() });
  };
  const dailyIds = [];
  for (let age = 8; age >= 1; age -= 1) {
    const id = randomUUID(); dailyIds.push(id); await seed('daily', age, id);
  }
  const oldPreMigrationId = randomUUID();
  const latestPreMigrationId = randomUUID();
  await seed('pre_migration', 20, oldPreMigrationId);
  await seed('pre_migration', 2, latestPreMigrationId);
  await writeFile(join(backupRoot, '.beta-backup-schedule.json'), jsonBytes({
    schemaVersion: 'beta-backup-schedule-state/v1',
    lastSuccessfulAt: new Date(now.valueOf() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    lastCheckpointId: dailyIds[0], lastCheckpointKind: 'daily', keepCheckpointIds: dailyIds,
    retiredCheckpointIds: [], officialEvidenceSha256: 'd'.repeat(64),
  }), { flag: 'wx', mode: 0o600 });

  const executeCheckpoint = (args) => writeCheckpoint(args);
  const verifyOfficialSource = async ({ checkpointDirectory, inventory }) => {
    const actual = await inspectBackupFile(checkpointDirectory, 'database.dump', 'database');
    assert.deepEqual(actual, inventory.files[0]);
    return { status: 'verified', sourceStable: true, sha256: sha(`${inventory.checkpointId}:${inventory.kind}:${inventory.capturedAt}`) };
  };
  const daily = await runDailyBackupScheduler({ backupRoot, now: nowIso,
    executeCheckpoint, verifyOfficialSource });
  assert.equal(daily.status, 'checkpoint_scheduled_and_rotated');
  assert.equal(daily.kind, 'daily');
  assert.equal(checkpointRows.length, 11, 'one overdue invocation creates one catch-up checkpoint, not one per missed day');
  assert.equal(daily.keepCheckpointIds.length, 8);
  const firstKept = await readdir(backupRoot);
  const firstKeptInventories = [];
  for (const id of daily.keepCheckpointIds) {
    const directory = join(backupRoot, id.replaceAll('-', ''));
    firstKeptInventories.push(JSON.parse(await readFile(join(directory, 'inventory.json'), 'utf8')));
  }
  assert.equal(firstKeptInventories.filter((item) => item.kind === 'daily').length, 7);
  assert.equal(firstKeptInventories.filter((item) => item.kind === 'pre_migration').length, 1);
  assert.ok(daily.keepCheckpointIds.includes(latestPreMigrationId));
  assert.ok(!daily.keepCheckpointIds.includes(oldPreMigrationId));
  assert.ok(firstKept.includes(`${oldPreMigrationId.replaceAll('-', '')}`) === false);
  for (const id of daily.retiredCheckpointIds) {
    await assert.rejects(readFile(join(backupRoot, id.replaceAll('-', ''), 'inventory.json')), { code: 'ENOENT' });
    const receipt = JSON.parse(await readFile(join(backupRoot, 'retirement-journal', `${id}.complete.json`), 'utf8'));
    assert.equal(receipt.status, 'retired');
    assert.equal(receipt.checkpointId, id);
  }

  const notDue = await runDailyBackupScheduler({ backupRoot, now: new Date(now.valueOf() + 5 * 60 * 1000).toISOString(),
    executeCheckpoint, verifyOfficialSource });
  assert.equal(notDue.status, 'not_due');
  assert.equal(checkpointRows.length, 11);

  const preMigration = await runDailyBackupScheduler({ backupRoot, requestedKind: 'pre_migration',
    now: new Date(now.valueOf() + 60 * 60 * 1000).toISOString(), executeCheckpoint, verifyOfficialSource });
  assert.equal(preMigration.status, 'checkpoint_scheduled_and_rotated');
  assert.equal(preMigration.kind, 'pre_migration');
  assert.equal(checkpointRows.length, 12);
  const finalInventories = [];
  for (const id of preMigration.keepCheckpointIds) {
    finalInventories.push(JSON.parse(await readFile(join(backupRoot, id.replaceAll('-', ''), 'inventory.json'), 'utf8')));
  }
  assert.equal(finalInventories.filter((item) => item.kind === 'daily').length, 7);
  assert.equal(finalInventories.filter((item) => item.kind === 'pre_migration').length, 1);
  const newestPreMigration = finalInventories.find((item) => item.kind === 'pre_migration');
  assert.equal(newestPreMigration.checkpointId, preMigration.checkpointId);
  assert.equal(newestPreMigration.capturedAt, new Date(now.valueOf() + 60 * 60 * 1000).toISOString());
  assert.equal(preMigration.writesMayBeEnabled, false);
});
