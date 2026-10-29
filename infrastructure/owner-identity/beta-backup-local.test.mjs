import assert from 'node:assert/strict';
import test from 'node:test';
import { benchmarkStateFingerprint } from './beta-backup-local.mjs';

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
