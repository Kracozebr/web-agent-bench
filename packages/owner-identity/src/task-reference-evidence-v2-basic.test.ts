import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { TaskCaseSchema, type TaskReleaseManifest } from './task-release.js';
import { verifyTaskReferenceEvidenceV2 } from './task-reference-evidence-v2.js';
import { verifyBasicV2ReferenceGoal } from './task-reference-evidence-v2-basic.js';
import type { V2Action, V2ReferenceContext } from './task-reference-evidence-v2-types.js';

const repositoryRoot = resolve(import.meta.dirname, '../../..');
const candidateRelative = 'artifacts/runs/bts-difficulty-v2-case-candidates/8f478f5f-edda-47f8-85b2-35fa2f455a4c/candidate-cases.json';
const candidateSha256 = 'b50836aa76611fe826e4c31e3fcc20f3cedb6e2e05485c0c59d11c79c0462156';
const policyRelative = 'infrastructure/owner-identity/task-release-local-policy.json';
const basicTaskIds = new Set(['S1', 'S2', 'S3', 'S4', 'M3']);
const asReferenceContext = (value: object) => value as unknown as V2ReferenceContext;

test('basic v2 verifier rejects task IDs outside its scope', async () => {
  const context = asReferenceContext({ taskCase: { taskId: 'U1' }, actions: [] });
  await assert.rejects(verifyBasicV2ReferenceGoal(context), { code: 'v2_basic_task_not_supported' });
});

test('basic v2 verifier fails closed when a supported case has no required participant action', async () => {
  const context = asReferenceContext({ taskCase: { taskId: 'S1' }, actions: [] });
  await assert.rejects(verifyBasicV2ReferenceGoal(context), { code: 'v2_basic_action_plan_mismatch' });
});

test('basic v2 verifier fails closed when the raw HTTP witness is missing', async () => {
  const action: V2Action = { kind: 'inspect_offer', operationId: '3729d84c-928d-432f-a9a2-8886a9997f25',
    rawResponsePath: 'case/response.json', rawResponseSha256: '0'.repeat(64) };
  const context = asReferenceContext({ taskCase: { taskId: 'S2' }, actions: [action],
    action: () => ({ operationId: action.operationId }), http: () => [], actualDocuments: [],
    generation: { generationId: 'ebd21150-8188-4c4d-8aa1-88c49af3bc97' } });
  await assert.rejects(verifyBasicV2ReferenceGoal(context), { code: 'v2_basic_actual_http_witness_missing' });
});

test('basic v2 semantic verifier proves retained captures (opt in with BEF_V2_BASIC_CAPTURE_TEST=1)', {
  skip: process.env.BEF_V2_BASIC_CAPTURE_TEST === '1' ? false : 'retained run artifacts are optional for the default unit suite',
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
    .filter((taskCase) => basicTaskIds.has(taskCase.taskId));
  assert.equal(cases.length, 9, 'five ranked and four training basic captures are retained');

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
