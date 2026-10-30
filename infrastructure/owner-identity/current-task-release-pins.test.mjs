import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { CURRENT_TASK_RELEASE_INPUTS_PATH, CURRENT_TASK_RELEASE_POINTER_PATH,
  loadCurrentTaskReleaseInputPins, loadCurrentTaskReleasePins } from './current-task-release-pins.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const captureId = '11111111-1111-4111-8111-111111111111';
const pins = () => ({
  cases: { path: `artifacts/runs/bts-difficulty-v2-case-candidates/${captureId}/candidate-cases.json`, sha256: sha256('cases') },
  release: { path: `artifacts/runs/bts-difficulty-v2-release-candidates/${captureId}/candidate-release.json`, sha256: sha256('release') },
  minimum: { path: `artifacts/runs/bts-v2-minimum-action-review/${captureId}/review.json`, sha256: sha256('minimum') },
  references: { path: `artifacts/runs/bts-v2-reference-verification/${captureId}/verification.json`, sha256: sha256('references') },
});

async function withRoot(callback) {
  const root = await mkdtemp(resolve(tmpdir(), 'current-task-release-pins-'));
  try { await callback(root); } finally { await rm(root, { recursive: true, force: true }); }
}

async function writeJson(root, path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  await mkdir(dirname(resolve(root, path)), { recursive: true });
  await writeFile(resolve(root, path), bytes);
  return sha256(bytes);
}

async function writeValidInputsConfig(root, artifactPins = pins()) {
  await writeJson(root, CURRENT_TASK_RELEASE_INPUTS_PATH, {
    schemaVersion: 'bts-current-task-release-inputs/v1',
    classification: 'current_candidate_artifact_pinset_not_validation_or_activation',
    ...artifactPins,
  });
}

async function writeValidPointer(root, overrides = {}) {
  const artifactPins = pins();
  await writeValidInputsConfig(root, artifactPins);
  const inputsConfigHash = sha256(await readFile(resolve(root, CURRENT_TASK_RELEASE_INPUTS_PATH)));
  const loaderPath = 'infrastructure/owner-identity/current-task-release-pins.mjs';
  const loaderHash = await writeJson(root, loaderPath, { fixture: true });
  for (const [key, pin] of Object.entries(artifactPins)) {
    await mkdir(dirname(resolve(root, pin.path)), { recursive: true });
    await writeFile(resolve(root, pin.path), key);
  }
  const validation = {
    schemaVersion: 'bts-difficulty-v2-offline-release-validation/v1',
    status: 'validated_candidate', sourceUnchanged: true,
    manifestBinding: { boundManifestHash: sha256('manifest'), participantToolProtocol: 'separate_payment_delivery_v2',
      difficultyReviewEvidence: artifactPins.minimum },
    sources: { caseCandidate: artifactPins.cases, releaseCandidate: artifactPins.release,
      minimumActionReview: artifactPins.minimum, semanticReferenceReview: artifactPins.references },
    sourceInputs: [
      ...Object.values(artifactPins),
      { path: CURRENT_TASK_RELEASE_INPUTS_PATH, sha256: inputsConfigHash },
      { path: loaderPath, sha256: loaderHash },
    ],
    claims: { releaseCandidateValidated: true, productReleaseActivated: false,
      ownerRunAcceptance: false, taskGrade: false },
    ...overrides,
  };
  const validationPath = `artifacts/runs/bts-difficulty-v2-release-validation/${captureId}/validation.json`;
  const validationHash = await writeJson(root, validationPath, validation);
  await writeJson(root, CURRENT_TASK_RELEASE_POINTER_PATH, {
    schemaVersion: 'bts-current-task-release-pointer/v1',
    classification: 'local_current_validated_release_reference',
    validation: { path: validationPath, sha256: validationHash },
  });
  return { artifactPins, validationPath };
}

test('current input pinset accepts only the current four artifact categories and safe SHA-256 references', async () => {
  await withRoot(async (root) => {
    await writeValidInputsConfig(root);
    const result = await loadCurrentTaskReleaseInputPins(root);
    assert.deepEqual(Object.keys(result).sort(), ['cases', 'inputsConfig', 'minimum', 'references', 'release'].sort());
    assert.equal(result.cases.path, pins().cases.path);
    assert.match(result.inputsConfig.sha256, /^[0-9a-f]{64}$/);
  });
});

test('current input pinset rejects path traversal and malformed artifact hashes', async () => {
  await withRoot(async (root) => {
    const badPath = pins();
    badPath.cases.path = '../candidate-cases.json';
    await writeValidInputsConfig(root, badPath);
    await assert.rejects(loadCurrentTaskReleaseInputPins(root), { message: 'current_cases_artifact_pin_invalid' });

    const badHash = pins();
    badHash.release.sha256 = 'A'.repeat(64);
    await writeValidInputsConfig(root, badHash);
    await assert.rejects(loadCurrentTaskReleaseInputPins(root), { message: 'current_release_artifact_pin_invalid' });
  });
});

test('post-validation pointer accepts only a hash-bound validated current artifact set', async () => {
  await withRoot(async (root) => {
    const expected = await writeValidPointer(root);
    const result = await loadCurrentTaskReleasePins(root);
    assert.deepEqual(result.cases, expected.artifactPins.cases);
    assert.equal(result.validation.path, expected.validationPath);
  });
});

test('post-validation pointer rejects traversal and validation hash mismatches', async () => {
  await withRoot(async (root) => {
    await writeValidPointer(root);
    const pointerPath = resolve(root, CURRENT_TASK_RELEASE_POINTER_PATH);
    const pointer = JSON.parse(await readFile(pointerPath, 'utf8'));
    pointer.validation.sha256 = '0'.repeat(64);
    await writeFile(pointerPath, `${JSON.stringify(pointer)}\n`);
    await assert.rejects(loadCurrentTaskReleasePins(root), { message: 'release_pin_hash_or_stability_invalid' });

    pointer.validation.path = '../validation.json';
    await writeFile(pointerPath, `${JSON.stringify(pointer)}\n`);
    await assert.rejects(loadCurrentTaskReleasePins(root), { message: 'current_validation_artifact_pin_invalid' });
  });
});

test('post-validation pointer rejects false validation claims and artifact-pin mismatches', async () => {
  await withRoot(async (root) => {
    const expected = await writeValidPointer(root, { claims: { releaseCandidateValidated: false,
      productReleaseActivated: false, ownerRunAcceptance: false, taskGrade: false } });
    await assert.rejects(loadCurrentTaskReleasePins(root), { message: 'current_release_validation_not_authoritative' });

    const validationPath = resolve(root, expected.validationPath);
    const validation = JSON.parse(await readFile(validationPath, 'utf8'));
    validation.claims.releaseCandidateValidated = true;
    validation.sources.caseCandidate.sha256 = 'f'.repeat(64);
    const validationHash = await writeJson(root, expected.validationPath, validation);
    await writeJson(root, CURRENT_TASK_RELEASE_POINTER_PATH, {
      schemaVersion: 'bts-current-task-release-pointer/v1',
      classification: 'local_current_validated_release_reference',
      validation: { path: expected.validationPath, sha256: validationHash },
    });
    await assert.rejects(loadCurrentTaskReleasePins(root), { message: 'current_release_validation_artifact_binding_missing' });
  });
});
