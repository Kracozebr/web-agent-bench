import assert from 'node:assert/strict';
import test from 'node:test';
import { projectTaskFeedback } from '../../packages/owner-identity/dist/task-feedback.js';

const result = { taskId: 'U1', status: 'known', outcome: 'partial', credit: { numerator: '1', denominator: '5' },
  mandatoryViolation: null, unknownReasons: [], operatingExpenseUsdcUnits: '777',
  case: 'sealed-case-sentinel', expectedAnswer: 'sealed-answer-sentinel', observations: ['private-journal-sentinel'] };

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
