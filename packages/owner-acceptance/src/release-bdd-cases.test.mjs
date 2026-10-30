import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createReleaseNegativeCandidates, expectedReleaseReferenceCount } from './release-bdd-cases.mjs';

const fixturePath = process.env.BTS_RELEASE_PROBE_FIXTURE;

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
