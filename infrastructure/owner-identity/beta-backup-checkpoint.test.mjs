import assert from 'node:assert/strict';
import test from 'node:test';
import { validateOfficialEvidenceBounds, validateOfficialEvidenceSourceBinding } from './beta-backup-checkpoint.mjs';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const hash = (character) => character.repeat(64);

test('official evidence bounds accept the exact restore-supported limits without allocating payload bytes', () => {
  assert.equal(validateOfficialEvidenceBounds({ fileCount: 4096, minFileBytes: 1, maxFileBytes: 64 * MiB,
    totalBytes: 2 * GiB, manifestBytes: 16 * MiB }), true);
  assert.equal(validateOfficialEvidenceBounds({ fileCount: 3, observedFileCount: 1,
    minFileBytes: 12, maxFileBytes: 12, totalBytes: 12 }), true);
  assert.throws(() => validateOfficialEvidenceBounds({ fileCount: 3, observedFileCount: 2,
    minFileBytes: 12, maxFileBytes: 12, totalBytes: 12 }),
  /beta_backup_checkpoint_official_evidence_total_size_invalid/);
});

test('official evidence bounds reject count, empty/oversize file, total and manifest boundary violations', () => {
  const count = (overrides = {}) => validateOfficialEvidenceBounds({ fileCount: 4097, ...overrides });
  assert.throws(() => count(), /beta_backup_checkpoint_official_evidence_file_count_invalid/);
  assert.throws(() => validateOfficialEvidenceBounds({ fileCount: 1, minFileBytes: 0, maxFileBytes: 0,
    totalBytes: 0 }), /beta_backup_checkpoint_official_evidence_file_size_invalid/);
  assert.throws(() => validateOfficialEvidenceBounds({ fileCount: 1, minFileBytes: 1,
    maxFileBytes: 64 * MiB + 1, totalBytes: 64 * MiB + 1 }), /beta_backup_checkpoint_official_evidence_file_size_invalid/);
  assert.throws(() => validateOfficialEvidenceBounds({ fileCount: 1, minFileBytes: 1, maxFileBytes: 1,
    totalBytes: 2 * GiB + 1 }), /beta_backup_checkpoint_official_evidence_total_size_invalid/);
  assert.throws(() => validateOfficialEvidenceBounds({ fileCount: 1, minFileBytes: 1, maxFileBytes: 1,
    totalBytes: 1, manifestBytes: 16 * MiB + 1 }), /beta_backup_checkpoint_official_evidence_manifest_size_invalid/);
});

test('official evidence source binding preserves callers without hashes and strictly checks supplied bytes and digest', () => {
  const actualSha256 = hash('a');
  const observation = { actualBytes: 24, actualSha256 };
  assert.equal(validateOfficialEvidenceSourceBinding(observation), true);
  assert.equal(validateOfficialEvidenceSourceBinding({ ...observation, expectedBytes: 24, expectedSha256: actualSha256 }), true);
  assert.throws(() => validateOfficialEvidenceSourceBinding({ ...observation, expectedSha256: 'not-a-hash' }),
    /beta_backup_checkpoint_official_evidence_expected_hash_invalid/);
  assert.throws(() => validateOfficialEvidenceSourceBinding({ ...observation, expectedSha256: hash('b') }),
    /beta_backup_checkpoint_official_evidence_expected_hash_mismatch/);
  assert.throws(() => validateOfficialEvidenceSourceBinding({ ...observation, expectedBytes: 25 }),
    /beta_backup_checkpoint_official_evidence_expected_bytes_mismatch/);
  assert.throws(() => validateOfficialEvidenceSourceBinding({ actualBytes: 0, actualSha256 }),
    /beta_backup_checkpoint_official_evidence_source_observation_invalid/);
});
