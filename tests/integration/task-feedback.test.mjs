import assert from 'node:assert/strict';
import test from 'node:test';
import { getOwnerRunFeedback, projectTaskFeedback } from '../../packages/owner-identity/dist/task-feedback.js';
import { sha256CanonicalTaskJson } from '../../packages/owner-identity/dist/task-release.js';
import { CLOSED_TRAINING_IDS, CURRENT_TRAINING_TASK_IDS, TASK_IDS } from '../../packages/owner-identity/dist/task-catalog.js';

const result = { taskId: 'U1', status: 'known', outcome: 'partial', credit: { numerator: '1', denominator: '5' },
  mandatoryViolation: null, unknownReasons: [], operatingExpenseUsdcUnits: '777',
  case: 'sealed-case-sentinel', expectedAnswer: 'sealed-answer-sentinel', observations: ['private-journal-sentinel'] };

function evaluationRow(taskId) {
  const taskResult = { taskId, status: 'known', outcome: 'passed', credit: { numerator: '1', denominator: '1' },
    mandatoryViolation: null, unknownReasons: [] };
  return { task_id: taskId, result_json: taskResult, result_hash: sha256CanonicalTaskJson(taskResult) };
}

function feedbackDb(mode, rows) {
  const responses = [[{ mode, status: 'completed' }], rows];
  return { execute: async () => responses.shift() };
}

test('closed feedback exposes exact credit and allowed reason without case or journal', () => {
  const projected = projectTaskFeedback(result);
  assert.deepEqual(projected, { taskId: 'U1', status: 'known', outcome: 'partial', credit: { numerator: '1', denominator: '5' }, reason: 'goal_unmet' });
  assert.equal(JSON.stringify(projected).includes('sentinel'), false);
});

test('unknown feedback keeps credit absent and never discloses diagnostic internals', () => {
  assert.deepEqual(projectTaskFeedback({ ...result, status: 'unknown', outcome: 'unknown', credit: null,
    unknownReasons: ['private-observer-path-sentinel'] }), {
    taskId: 'U1', status: 'unknown', outcome: 'unknown', credit: null, reason: 'evidence_unknown',
  });
});

test('mandatory violation feedback does not reveal private observation identifiers', () => {
  const projected = projectTaskFeedback({ ...result, outcome: 'failed', credit: { numerator: '0', denominator: '1' },
    mandatoryViolation: { rule: 'scope-violation-sentinel', observationIds: ['private-id-sentinel'] } });
  assert.equal(projected.reason, 'budget_reserve_permission_scope_violation');
  assert.equal(JSON.stringify(projected).includes('sentinel'), false);
});

test('training feedback includes only current training tasks while ranked feedback retains all tasks', async () => {
  assert.deepEqual(CLOSED_TRAINING_IDS, ['S2', 'S3', 'S4', 'M2', 'M3', 'M4', 'H2', 'H3', 'U1']);
  const rows = TASK_IDS.map(evaluationRow);

  const training = await getOwnerRunFeedback(feedbackDb('training', rows), 'owner', 'training-run');
  assert.equal(training.status, 'available');
  assert.deepEqual(training.tasks.map(({ taskId }) => taskId), CURRENT_TRAINING_TASK_IDS);

  const ranked = await getOwnerRunFeedback(feedbackDb('ranked', rows), 'owner', 'ranked-run');
  assert.equal(ranked.status, 'available');
  assert.deepEqual(ranked.tasks.map(({ taskId }) => taskId), TASK_IDS);
});
