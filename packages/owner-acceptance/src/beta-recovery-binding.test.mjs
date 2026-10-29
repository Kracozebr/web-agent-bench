import assert from 'node:assert/strict';
import test from 'node:test';
import { recoveryDeadlineObservationState, recoveryExhaustionTerminalConditions,
  selectRecoveryActionBinding, waitForRecoveryExhaustionFinalization } from './beta-recovery-cases.mjs';

const environmentId = 'bef-env-a';
const generationId = '10000000-0000-4000-8000-000000000001';
const preparationId = '10000000-0000-4000-8000-000000000002';
const actionId = '20000000-0000-4000-8000-000000000001';
const laterActionId = '20000000-0000-4000-8000-000000000002';
const payloadHash = 'a'.repeat(64);
const recoveryRunId = '30000000-0000-4000-8000-000000000001';
const recoveryAgentId = '30000000-0000-4000-8000-000000000002';
const recoveryClaimId = '30000000-0000-4000-8000-000000000003';
const recoveryLeaseId = '30000000-0000-4000-8000-000000000004';
const cancellationFenceHash = 'b'.repeat(64);

function action(id, sequence, taskIndex, kind) {
  return { id, task_index: taskIndex, action_sequence: String(sequence), operation_id: `op_${id}`,
    action_kind: kind, payload_hash: payloadHash, environment_id: environmentId };
}

function snapshot({ taskId = 'S4', actions = [action(actionId, 2, 0, 'approve')], executionCount = 1 } = {}) {
  return { result: { tasks: [{ task_index: 0, task_id: taskId }], actions,
    execution: Array.from({ length: executionCount }, (_, index) => ({ task_index: index,
      env_id: environmentId, generation_id: generationId, preparation_id: preparationId,
      participant_id: `participant-${index}`, lease_id: '30000000-0000-4000-8000-000000000001' })) } };
}

test('S4 recovery binding selects the exact first action despite later task actions', () => {
  const value = selectRecoveryActionBinding(snapshot({ actions: [
    action(laterActionId, 10, 0, 'approve'), action(actionId, 2, 0, 'approve'),
  ] }), { taskId: 'S4', actionId, actionOrdinal: 0 });
  assert.equal(value.actionId, actionId);
  assert.equal(value.actionKind, 'approve');
  assert.equal(value.taskId, 'S4');
  assert.equal(value.taskIndex, 0);
  assert.equal(value.environmentId, environmentId);
});

test('M3 recovery binding reflects its actual first approve action', () => {
  const value = selectRecoveryActionBinding(snapshot({ taskId: 'M3' }), { taskId: 'M3' });
  assert.equal(value.actionKind, 'approve');
  assert.equal(value.taskId, 'M3');
});

test('recovery binding rejects a later action when the selected action is not first', () => {
  const value = snapshot({ actions: [action(actionId, 2, 0, 'approve'), action(laterActionId, 3, 0, 'approve')] });
  assert.throws(() => selectRecoveryActionBinding(value, { taskId: 'S4', actionId: laterActionId }),
    { code: 'recovery_action_generation_binding_missing' });
});

test('recovery binding rejects phantom cross-task actions and invalid action kinds', () => {
  assert.throws(() => selectRecoveryActionBinding(snapshot({ actions: [
    action(actionId, 1, 0, 'approve'), action(laterActionId, 2, 1, 'approve'),
  ] }), { taskId: 'S4' }), { code: 'recovery_action_generation_binding_missing' });
  assert.throws(() => selectRecoveryActionBinding(snapshot({ actions: [action(actionId, 1, 0, 'wrap')] }),
    { taskId: 'S4' }), { code: 'recovery_action_generation_binding_missing' });
});

test('recovery binding rejects duplicate sequences and multiple environments', () => {
  assert.throws(() => selectRecoveryActionBinding(snapshot({ actions: [
    action(actionId, 1, 0, 'approve'), action(laterActionId, 1, 0, 'approve'),
  ] }), { taskId: 'S4' }), { code: 'recovery_action_sequence_duplicate' });
  const mismatched = snapshot();
  mismatched.result.actions[0].environment_id = 'bef-env-b';
  assert.throws(() => selectRecoveryActionBinding(mismatched, { taskId: 'S4' }),
    { code: 'recovery_action_generation_binding_missing' });
  assert.throws(() => selectRecoveryActionBinding(snapshot({ executionCount: 2 }), { taskId: 'S4' }),
    { code: 'recovery_action_generation_binding_missing' });
});

test('recovery deadline treats unknown as active while the fixed window is open', () => {
  const startedAt = '2030-01-01T00:00:00.000Z';
  const row = { started_at: startedAt, deadline_at: '2030-01-01T00:03:00.000Z', status: 'unknown' };
  const state = recoveryDeadlineObservationState(row, '2030-01-01T00:02:59.999Z');
  assert.equal(state.deadlineReached, false);
  assert.equal(state.deadlineMs - state.startedMs, 180_000);
});

test('recovery deadline accepts an active unknown row only after the fixed window', () => {
  const row = { started_at: '2030-01-01T00:00:00.000Z',
    deadline_at: '2030-01-01T00:03:00.000Z', status: 'unknown' };
  assert.equal(recoveryDeadlineObservationState(row, '2030-01-01T00:03:00.999Z').deadlineReached, false);
  assert.equal(recoveryDeadlineObservationState(row, '2030-01-01T00:03:01.000Z').deadlineReached, true);
});

test('recovery deadline rejects early success and premature exhaustion/refund states', () => {
  const startedAt = '2030-01-01T00:00:00.000Z';
  const deadlineAt = '2030-01-01T00:03:00.000Z';
  assert.throws(() => recoveryDeadlineObservationState({ started_at: startedAt, deadline_at: deadlineAt,
    status: 'recovered' }, '2030-01-01T00:00:10.000Z'), { code: 'recovery_exhaustion_status_invalid' });
  for (const status of ['exhausted', 'refunded']) {
    assert.throws(() => recoveryDeadlineObservationState({ started_at: startedAt, deadline_at: deadlineAt, status },
      '2030-01-01T00:02:59.999Z'), { code: 'recovery_exhaustion_terminal_state_pre_deadline' });
  }
});

test('recovery deadline rejects a row whose persisted duration differs from 180 seconds', () => {
  assert.throws(() => recoveryDeadlineObservationState({ started_at: '2030-01-01T00:00:00.000Z',
    deadline_at: '2030-01-01T00:03:00.001Z', status: 'unknown' }, '2030-01-01T00:02:00.000Z'),
  { code: 'recovery_deadline_identity_invalid' });
});

function exhaustionSnapshot({ finalized = false, refundCount = finalized ? 1 : 0, includeFenceEvent = true,
  slots = finalized ? [] : [{ run_id: recoveryRunId, agent_id: recoveryAgentId, claim_id: recoveryClaimId,
    state: 'running', released_at: null }] } = {}) {
  const run = { id: recoveryRunId, agent_id: recoveryAgentId,
    status: finalized ? 'failed' : 'running', terminal_reason: finalized ? 'platform_failure_recovery_exhausted' : null,
    cancellation_reason: finalized ? 'coordinator_platform_failure' : null,
    cancellation_evidence_hash: finalized ? cancellationFenceHash : null };
  return { result: {
    run,
    recovery: { status: finalized ? 'refunded' : 'exhausted' },
    refunds: Array.from({ length: refundCount }, (_, index) => ({ operation_id: `runref_${index}` })),
    slots,
    claims: [{ run_id: recoveryRunId, claim_id: recoveryClaimId, status: finalized ? 'released' : 'claimed',
      released_at: finalized ? '2030-01-01T00:03:03.000Z' : null }],
    execution: [{ run_id: recoveryRunId, task_index: 0, env_id: environmentId, generation_id: generationId,
      preparation_id: preparationId, lease_id: recoveryLeaseId, lease_state: finalized ? 'fenced' : 'fencing',
      lease_fence_evidence: finalized ? { confirmed: true, preparationId, leaseId: recoveryLeaseId,
        environmentId, generationId, evidence: { boundary: 'actual_tool_http_x402_local_evm_application_store',
          sha256: 'c'.repeat(64) } } : null }],
    terminalEvents: finalized && includeFenceEvent ? [{ run_id: recoveryRunId,
      event_type: 'run.cancelled.after_start', reason: 'coordinator_platform_failure',
      fence_evidence_hash: cancellationFenceHash }] : [],
  } };
}

test('observed source action is not terminal until failed run, one refund, released slot and fence persist', async () => {
  const snapshots = [exhaustionSnapshot(), exhaustionSnapshot(), exhaustionSnapshot({ finalized: true })];
  let reads = 0;
  let nowMs = 0;
  const result = await waitForRecoveryExhaustionFinalization(async () => snapshots[Math.min(reads++, snapshots.length - 1)], {
    runId: '10000000-0000-4000-8000-000000000101',
    actionId: '20000000-0000-4000-8000-000000000101', maxWaitMs: 1_000, pollIntervalMs: 100,
    now: () => nowMs, sleep: async (durationMs) => { nowMs += durationMs; },
  });
  assert.equal(reads, 3);
  assert.equal(result.elapsedMs, 200);
  assert.equal(result.verified, true);
  assert.deepEqual(result.failedConditions, []);
});

test('exhaustion finalization timeout retains safe failed-condition names', async () => {
  let nowMs = 0;
  await assert.rejects(waitForRecoveryExhaustionFinalization(async () => exhaustionSnapshot(), {
    runId: '10000000-0000-4000-8000-000000000102',
    actionId: '20000000-0000-4000-8000-000000000102', maxWaitMs: 100, pollIntervalMs: 50,
    now: () => nowMs, sleep: async (durationMs) => { nowMs += durationMs; },
  }), (error) => {
    assert.equal(error.code, 'PLATFORM_RECOVERY_EXHAUSTION_FINALIZATION_TIMEOUT');
    assert.deepEqual(error.safeDiagnostic.failedConditions, [
      'runFailed', 'exhaustionTerminalReason', 'recoveryRefunded', 'exactlyOneRefund',
      'noActiveExecutionSlot', 'firstDispatchClaimReleasedAndRunBound', 'generationLeaseFenced',
      'cancellationFenceEventBound',
    ]);
    assert.equal(error.safeDiagnostic.current.refundCount, 0);
    assert.equal(error.safeDiagnostic.current.unfencedGenerationLeaseCount, 1);
    return true;
  });
});

test('exhaustion terminal predicate rejects partial or duplicated refund state', () => {
  const missingRefund = recoveryExhaustionTerminalConditions(exhaustionSnapshot({ finalized: true, refundCount: 0 }));
  assert.equal(missingRefund.verified, false);
  assert.ok(missingRefund.failedConditions.includes('exactlyOneRefund'));
  const duplicated = exhaustionSnapshot({ finalized: true });
  duplicated.result.refunds.push({ operation_id: 'runref_duplicate' });
  const duplicateRefund = recoveryExhaustionTerminalConditions(duplicated);
  assert.equal(duplicateRefund.verified, false);
  assert.deepEqual(duplicateRefund.failedConditions, ['exactlyOneRefund']);
});

test('a deleted slot is accepted only with run-bound released claim and exact cancellation fence evidence', () => {
  const deletedSlot = exhaustionSnapshot({ finalized: true, slots: [] });
  const valid = recoveryExhaustionTerminalConditions(deletedSlot);
  assert.equal(deletedSlot.result.slots.length, 0);
  assert.equal(valid.conditions.noActiveExecutionSlot, true);
  assert.equal(valid.conditions.firstDispatchClaimReleasedAndRunBound, true);
  assert.equal(valid.conditions.generationLeaseFenced, true);
  assert.equal(valid.conditions.cancellationFenceEventBound, true);
  assert.equal(valid.verified, true);

  const missingFenceEvent = recoveryExhaustionTerminalConditions(exhaustionSnapshot({ finalized: true,
    slots: [], includeFenceEvent: false }));
  assert.equal(missingFenceEvent.conditions.noActiveExecutionSlot, true);
  assert.equal(missingFenceEvent.verified, false);
  assert.deepEqual(missingFenceEvent.failedConditions, ['cancellationFenceEventBound']);
});
