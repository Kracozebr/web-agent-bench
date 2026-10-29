import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { benchmarkStateFingerprint, createLocalCombinedBackup } from './beta-backup-local.mjs';

test('combined benchmark fingerprint detects an oid_benchmark_run status-row change', () => {
  const before = {
    oid_benchmark_run: { rowCount: 1, sha256: 'a'.repeat(64) },
    oid_run_operation: { rowCount: 1, sha256: 'b'.repeat(64) },
    oid_task_preparation_generation: { rowCount: 1, sha256: 'c'.repeat(64) },
  };
  const after = {
    ...before,
    oid_benchmark_run: { rowCount: 1, sha256: 'd'.repeat(64) },
  };

  assert.notEqual(benchmarkStateFingerprint(before), benchmarkStateFingerprint(after));
});

test('restore rehearsal keeps its source stopped while ordinary checkpoints resume it', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'bpc-source-lifecycle-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const repoRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
  for (const holdForRestore of [false, true]) {
    let stopped = 0;
    let restarted = 0;
    const fixtureRoot = join(parent, holdForRestore ? 'restore' : 'checkpoint');
    const provider = await createLocalCombinedBackup({
      repoRoot,
      databaseUrl: 'postgres://oid_owner@postgres:5432/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      observerDatabaseUrl: 'postgres://oid_observer@postgres:5432/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      privateDataDir: join(fixtureRoot, 'private-data'), closureStatePath: join(fixtureRoot, 'closure.json'),
      sourceBuildSha256: 'a'.repeat(64), officialEvidenceRefs: {}, getRuntimeRecoverySecrets: async () => ({}),
      stopApi: async () => { stopped += 1; }, restartApi: async () => { restarted += 1; },
      hostBridgeRoot: join(fixtureRoot, 'jobs'), hostOperatorRoot: join(fixtureRoot, 'operator'),
      backupRoot: join(fixtureRoot, 'backups'), restoreRoot: join(fixtureRoot, 'restores'),
      ...(holdForRestore ? { resumeSourceAfterCheckpoint: false } : {}),
    });
    await provider.checkpointAdapters.acquireAdmissionFreeze();
    await provider.checkpointAdapters.releaseAdmissionFreeze();
    assert.equal(stopped, 1);
    assert.equal(restarted, holdForRestore ? 0 : 1);
  }
});
