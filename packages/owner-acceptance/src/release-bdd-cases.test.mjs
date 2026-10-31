import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createReleaseNegativeCandidates, expectedReleaseReferenceCount } from './release-bdd-cases.mjs';

const fixturePath = process.env.BTS_RELEASE_PROBE_FIXTURE;
const currentFixturePath = process.env.BTS_RELEASE_CURRENT_FIXTURE;

test('release probe expects verified reference rows for the manifest case inventory', () => {
  const manifest = {
    cases: {
      training: [{}, {}, {}],
      ranked: Array.from({ length: 12 }, () => ({})),
    },
  };
  assert.equal(expectedReleaseReferenceCount(manifest), 15);
  assert.equal(expectedReleaseReferenceCount({ cases: { training: [], ranked: [] } }), 0);
  assert.equal(expectedReleaseReferenceCount({ cases: { training: [] } }), null);
});

test('current release generates real malformed catalog controls and an otherwise valid immutable-identity collision', {
  skip: !currentFixturePath,
}, async () => {
  const capture = JSON.parse(await readFile(currentFixturePath, 'utf8'));
  const source = capture?.release?.manifest;
  const releaseApi = await import('../../owner-identity/dist/task-release.js');
  assert.equal(releaseApi.TaskReleaseManifestSchema.safeParse(source).success, true,
    'current-profile raw manifest is required, not a substituted synthetic catalog');
  const probes = createReleaseNegativeCandidates(source, releaseApi);
  assert.equal(probes.length, 21);
  assert.equal(new Set(probes.map((probe) => probe.id)).size, 21);
  const expectations = {
    training_set_mismatch: ['inventory.openTrainingTaskIds.1'],
    training_weight_or_sum_mismatch: ['inventory.openTrainingWeightSum'],
    ranked_or_training_case_count_mismatch: ['cases.training', 'cases.ranked'],
  };
  for (const [id, paths] of Object.entries(expectations)) {
    const probe = probes.find((item) => item.id === id);
    assert.ok(probe?.candidate, id);
    const parsed = releaseApi.TaskReleaseManifestSchema.safeParse(probe.candidate);
    assert.equal(parsed.success, false, id);
    const result = await releaseApi.validateTaskReleaseCandidate(probe.candidate, {
      verifyFeasibility: async () => assert.fail('malformed catalog reached external verifier'),
      verifyReferencePath: async () => assert.fail('malformed catalog reached external verifier'),
      verifyDifficultyReview: async () => assert.fail('malformed catalog reached external verifier'),
    });
    assert.equal(result.status, 'blocked', id);
    for (const path of paths) assert.ok(result.blockers.some((blocker) =>
      blocker.code === 'manifest_schema_invalid' && blocker.subject === path), `${id}: ${path}`);
    assert.equal(probe.candidate.policyHash, releaseApi.taskPolicyHash(probe.candidate));
    assert.equal(probe.candidate.manifestHash, releaseApi.sha256CanonicalTaskJson(
      Object.fromEntries(Object.entries(probe.candidate).filter(([key]) => key !== 'manifestHash'))));
  }
  const reuse = probes.find((item) => item.id === 'release_identity_reuse');
  assert.equal(releaseApi.TaskReleaseManifestSchema.safeParse(reuse.candidate).success, true);
  assert.equal(reuse.candidate.releaseIdentity, source.releaseIdentity);
  assert.notEqual(reuse.candidate.manifestHash, source.manifestHash);
  assert.deepEqual(reuse.candidate.cases, source.cases,
    'identity reuse must reach immutable-store rejection, not a new case/reference failure');
  assert.deepEqual(reuse.candidate.executionIdentity, source.executionIdentity);
  assert.equal(reuse.candidate.policyHash, source.policyHash);
  assert.equal(reuse.expected.activationErrorCode, 'release_identity_immutable_conflict');
});

test('retained release fixture produces a bounded, production-blocked initially satisfied U1 allocation', {
  skip: !fixturePath,
}, async () => {
  const capture = JSON.parse(await readFile(fixturePath, 'utf8'));
  const baseManifest = capture?.release?.manifest;
  assert.ok(baseManifest && Array.isArray(capture?.variants), 'retained release probe fixture is malformed');

  const releaseApi = await import('../../owner-identity/dist/task-release.js');
  const previousVariant = capture.variants.find((variant) => variant?.id === 'initially_satisfied_u1_allocation');
  const previousCandidate = previousVariant?.candidateManifest;
  assert.ok(previousCandidate, 'retained failing candidate is missing');
  const previousParse = releaseApi.TaskReleaseManifestSchema.safeParse(previousCandidate);
  assert.equal(previousParse.success, false, 'retained old candidate should reproduce the schema overflow');
  const previousU1 = previousCandidate.cases.ranked.find((taskCase) => taskCase.taskId === 'U1');
  assert.ok(previousU1.initialState.balances.some((balance) => balance.amountUnits.length > 78),
    'retained old candidate should contain the out-of-range base-unit amount');

  const probe = createReleaseNegativeCandidates(baseManifest, releaseApi)
    .find((candidate) => candidate.id === 'initially_satisfied_u1_allocation');
  assert.ok(probe?.candidate, `bounded candidate generation failed: ${probe?.generationErrorCode ?? 'missing_candidate'}`);
  const parsed = releaseApi.TaskReleaseManifestSchema.safeParse(probe.candidate);
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues));

  let verifierCalls = 0;
  const blocked = await releaseApi.validateTaskReleaseCandidate(probe.candidate, {
    verifyFeasibility: async () => { verifierCalls += 1; throw new Error('static blocker should run before verifier'); },
    verifyReferencePath: async () => { verifierCalls += 1; throw new Error('static blocker should run before verifier'); },
    verifyDifficultyReview: async () => { verifierCalls += 1; throw new Error('static blocker should run before verifier'); },
  });
  assert.equal(blocked.status, 'blocked');
  assert.ok(blocked.blockers.some((row) => row.code === 'invalid_u1_fixed_sets' && row.subject.startsWith('ranked/U1/')),
    'production release validator must reject the real initially-satisfied allocation predicate');
  assert.equal(verifierCalls, 0, 'the U1 fixed-set blocker must be detected by the production static validator');
});
