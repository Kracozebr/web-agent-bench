import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { TaskCaseSchema, type TaskReleaseManifest } from './task-release.js';
import { verifyTaskReferenceEvidenceV2 } from './task-reference-evidence-v2.js';
import { advancedStateAccountMatches } from './task-reference-evidence-v2-advanced.js';

const repositoryRoot = resolve(import.meta.dirname, '../../..');
const candidateRelative = 'artifacts/runs/bts-difficulty-v2-case-candidates/8f478f5f-edda-47f8-85b2-35fa2f455a4c/candidate-cases.json';
const candidateSha256 = 'b50836aa76611fe826e4c31e3fcc20f3cedb6e2e05485c0c59d11c79c0462156';
const policyRelative = 'infrastructure/owner-identity/task-release-local-policy.json';
const advancedTaskIds = new Set(['M1', 'M2', 'H1', 'H2', 'M4', 'H3', 'U1']);

test('participant balance alias applies only to participant or the exact payer address', () => {
  const payer = `0x${'11'.repeat(20)}`;
  const recipient = `0x${'22'.repeat(20)}`;
  assert.equal(advancedStateAccountMatches('participant', 'participant', payer), true);
  assert.equal(advancedStateAccountMatches('participant', payer, payer), true);
  assert.equal(advancedStateAccountMatches(payer, payer, payer), true);
  assert.equal(advancedStateAccountMatches('participant', recipient, payer), false);
  assert.equal(advancedStateAccountMatches(recipient, recipient, payer), true);
});

test('advanced v2 verifier proves retained captures through the common state-hash wrapper (opt in with BEF_V2_ADVANCED_CAPTURE_TEST=1)', {
  skip: process.env.BEF_V2_ADVANCED_CAPTURE_TEST === '1' ? false : 'retained run artifacts are optional for the default unit suite',
}, async (t) => {
  const candidateBytes = await readFile(resolve(repositoryRoot, candidateRelative));
  assert.equal(createHash('sha256').update(candidateBytes).digest('hex'), candidateSha256,
    'retained candidate inventory must match its review pin');
  const candidate = JSON.parse(candidateBytes.toString('utf8')) as {
    executionIdentity: Record<string, unknown>;
    executionIdentityHash: string;
    cases: unknown[];
  };
  const policyBytes = await readFile(resolve(repositoryRoot, policyRelative));
  const profilePolicy = { path: policyRelative, sha256: createHash('sha256').update(policyBytes).digest('hex') };
  const cases = candidate.cases.map((value) => TaskCaseSchema.parse(value))
    .filter((taskCase) => advancedTaskIds.has(taskCase.taskId));
  assert.equal(cases.length, 11, 'seven ranked and four training advanced captures are retained');

  for (const taskCase of cases) {
    await t.test(`${taskCase.taskId}/${taskCase.mode}`, async () => {
      const result = await verifyTaskReferenceEvidenceV2({ repositoryRoot,
        identity: candidate.executionIdentity as TaskReleaseManifest['executionIdentity'],
        profilePolicy, evidence: taskCase.referencePath.evidence, taskCase,
        executionIdentityHash: candidate.executionIdentityHash });
      assert.equal(result.status, 'verified', result.status === 'verified' ? undefined : result.reason);
      if (result.status !== 'verified') return;
      assert.equal(result.actualBoundary, true);
      assert.equal(result.solvable, true);
      assert.equal(result.initiallySolved, false);
      assert.equal(result.actionCount, taskCase.referencePath.actionCount);
      assert.equal(result.initialStateSha256, taskCase.initialState.stateSha256);
      assert.equal(result.finalStateSha256, taskCase.referencePath.finalStateSha256);
    });
  }
});
