import assert from 'node:assert/strict';
import test from 'node:test';
import { OPEN_TASK_IDS, automaticWorkerCallbackFinancialBoundaryUnchanged, automaticWorkerChargeUnchanged,
  normalizeTrainingSequenceTaskIds,
  quoteTrainingSelectionUnits, trainingSequenceGrantAmountUnits,
  trainingCleanupLeasePrefixIsFenced, trainingSequenceTransitionBasis, trainingSequenceTransitions,
  trainingSuccessorActivationChainMatches, trainingSuccessorActivationResult,
  validateGenuineRecoveryProxySettings } from './genuine-s1-cases.mjs';

test('automatic worker charge invariance keeps prior owner refunds and lots as baseline', () => {
  const initial = { runId: '96e13ff8-bbfc-4cb0-bbab-d091bc9ab632', moneySha256: 'a'.repeat(64),
    ownerRefundCount: 1, runRefundCount: 0 };
  const current = { run: { id: initial.runId }, moneySha256: initial.moneySha256,
    ownerRefundCount: 1, runRefundCount: 0 };

  assert.equal(automaticWorkerChargeUnchanged(initial, current), true,
    'historical refunds and bonus lots already present at run start do not look like a new run charge');
  assert.equal(automaticWorkerChargeUnchanged(initial, { ...current, moneySha256: 'b'.repeat(64) }), false,
    'any owner-money change after this run starts remains a failure');
  assert.equal(automaticWorkerChargeUnchanged(initial, { ...current, ownerRefundCount: 2 }), false,
    'a newly added owner refund remains a failure');
  assert.equal(automaticWorkerChargeUnchanged(initial, { ...current, runRefundCount: 1 }), false,
    'a refund linked to this run remains a failure');
  assert.equal(automaticWorkerChargeUnchanged({ ...initial, runRefundCount: 1 }, current), false,
    'a refunded run cannot be used as a normal worker completion baseline');
  assert.equal(automaticWorkerChargeUnchanged(initial, { ...current, run: { id: '45bb8d13-e595-4802-9500-2c1382f043a3' } }), false,
    'money equality cannot bind a snapshot to a different run');
});

test('first-task orchestration rebases global money only after proving this run stayed unchanged', () => {
  const runId = '96e13ff8-bbfc-4cb0-bbab-d091bc9ab632';
  const ownerId = 'f7c4290f-5ce1-4cc3-9b84-5951ad7ba841';
  const agentId = '2ea94899-645a-4656-98a4-83e1c45d3950';
  const claimId = '772f4ffc-545d-46b5-99a8-f7a821462dc1';
  const before = {
    run: { id: runId, owner_id: ownerId, agent_id: agentId, status: 'running' },
    runMoneySha256: 'a'.repeat(64), moneySha256: 'b'.repeat(64),
    ownerLedgerSha256: 'c'.repeat(64), ownerLedgerCount: 4,
    ownerRefundCount: 0, runRefundCount: 0,
    claims: [{ claim_id: claimId, status: 'claimed', released_at: null }],
    slots: [{ run_id: runId, agent_id: agentId, claim_id: claimId, state: 'running', released_at: null }],
  };
  const after = { ...before, moneySha256: 'd'.repeat(64), ownerLedgerSha256: 'e'.repeat(64),
    ownerLedgerCount: 5 };

  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before, after,
    { runId, callbackName: 'onGenuineFirstTaskActive' }), true,
  'the explicit orchestration callback may change owner-wide money while this active run stays financially identical');
  assert.equal(automaticWorkerChargeUnchanged({ runId, moneySha256: before.moneySha256,
    ownerRefundCount: before.ownerRefundCount, runRefundCount: before.runRefundCount }, after), false,
  'the original whole-owner snapshot is not reused after the callback');
  assert.equal(automaticWorkerChargeUnchanged({ runId, moneySha256: after.moneySha256,
    ownerRefundCount: after.ownerRefundCount, runRefundCount: after.runRefundCount }, after), true,
  'the post-callback whole-owner snapshot remains the strict baseline for worker execution');

  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before,
    { ...after, runMoneySha256: 'f'.repeat(64) }, { runId, callbackName: 'onGenuineFirstTaskActive' }), false,
  'a new reservation, hold, run ledger entry, or run refund cannot be rebased');
  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before,
    { ...after, ownerRefundCount: 1 }, { runId, callbackName: 'onGenuineFirstTaskActive' }), false,
  'a callback-created owner refund cannot be rebased');
  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before,
    { ...after, runRefundCount: 1 }, { runId, callbackName: 'onGenuineFirstTaskActive' }), false,
  'a callback-created run refund cannot be rebased');
  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before,
    { ...after, claims: [{ ...after.claims[0], claim_id: '4f7dedc8-d33b-464c-ae9b-714cfba03b4a' }] },
    { runId, callbackName: 'onGenuineFirstTaskActive' }), false,
  'a changed dispatch claim cannot be rebased');
  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before,
    { ...after, slots: [{ ...after.slots[0], state: 'fenced' }] },
    { runId, callbackName: 'onGenuineFirstTaskActive' }), false,
  'a changed or inactive slot cannot be rebased');
  assert.equal(automaticWorkerCallbackFinancialBoundaryUnchanged(before, after,
    { runId, callbackName: 'beforeAction' }), false,
  'no other callback scope may move the baseline');
});

test('all-open training selection is canonical and contains seven adjacent transitions', () => {
  assert.deepEqual(OPEN_TASK_IDS, ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']);
  assert.deepEqual(normalizeTrainingSequenceTaskIds(OPEN_TASK_IDS), OPEN_TASK_IDS);
  assert.deepEqual(normalizeTrainingSequenceTaskIds(['S2', 'S1']), ['S1', 'S2']);
  assert.deepEqual(trainingSequenceTransitions(OPEN_TASK_IDS), OPEN_TASK_IDS.slice(1).map((toTaskId, index) => ({
    fromTaskIndex: index,
    fromTaskId: OPEN_TASK_IDS[index],
    toTaskIndex: index + 1,
    toTaskId,
  })));
});

test('training capture helper rejects empty, duplicate, closed, unknown and unsupported sequences', () => {
  for (const selection of [[], ['S1', 'S1'], ['S1', 'S3'], ['S1', 'UNKNOWN'], ['S2', 'S4'],
    ['S1', 'S2', 'S4'], ['S2', 'S1', 'S4'], [...OPEN_TASK_IDS].reverse()]) {
    assert.throws(() => normalizeTrainingSequenceTaskIds(selection), { code: 'unsupported_genuine_task_selection' });
  }
});

test('recovery proxy settings require explicit automatic worker and strict loopback endpoints', () => {
  assert.equal(validateGenuineRecoveryProxySettings(), null);
  assert.throws(() => validateGenuineRecoveryProxySettings({ apiBaseUrl: 'http://127.0.0.1:32123' }),
    { code: 'platform_recovery_proxy_requires_server_worker' });
  assert.deepEqual(validateGenuineRecoveryProxySettings({ automaticWorkerEvaluation: true,
    apiBaseUrl: 'http://127.0.0.1:32123', observerDatabase: { host: '127.0.0.1', port: 32124 } }), {
    participantApiOrigin: 'http://127.0.0.1:32123', observerDatabase: { host: '127.0.0.1', port: 32124, database: 'bef' },
  });
  for (const apiBaseUrl of ['https://127.0.0.1:32123', 'http://host.docker.internal:32123',
    'http://127.0.0.1:32123/path', 'http://user@127.0.0.1:32123', 'http://127.0.0.1']) {
    assert.throws(() => validateGenuineRecoveryProxySettings({ automaticWorkerEvaluation: true, apiBaseUrl }),
      { code: 'platform_recovery_proxy_api_origin_must_be_loopback' });
  }
  assert.throws(() => validateGenuineRecoveryProxySettings({ automaticWorkerEvaluation: true,
    observerDatabase: { host: 'host.docker.internal', port: 32124 } }),
  { code: 'platform_recovery_observer_proxy_must_be_loopback' });
});

test('training quote rounds the selected weight once and keeps the established S1/S2 grant floor', () => {
  const weights = [1, 1, 1, 2, 2, 2, 3, 3];
  const release = { trainingPriceUnits: '500000', trainingTasks: OPEN_TASK_IDS.map((taskId, index) => ({
    taskId, taskWeight: weights[index],
  })) };
  const s1s2Quote = quoteTrainingSelectionUnits(release, ['S1', 'S2']);
  const allOpenQuote = quoteTrainingSelectionUnits(release, OPEN_TASK_IDS);

  assert.equal(s1s2Quote, 66_667n);
  assert.equal(trainingSequenceGrantAmountUnits(s1s2Quote), 100_000n);
  assert.equal(allOpenQuote, 500_000n);
  assert.equal(trainingSequenceGrantAmountUnits(allOpenQuote), 500_000n);
});

test('all-open successor basis requires the immediate predecessor event and matching prior deadline', () => {
  const taskIds = [...OPEN_TASK_IDS];
  const transition = trainingSequenceTransitions(taskIds)[3]; // M1 -> M3
  const startDeadline = '2026-10-29T10:00:00.000Z';
  const predecessorDeadline = '2026-10-29T10:05:00.000Z';
  const runStartedEvents = [{ sequence: '1', payload: { overallDeadline: startDeadline } }];
  const activationEvents = [
    { sequence: '2', payload: { toTaskIndex: 1 } },
    { sequence: '3', payload: { toTaskIndex: 2 } },
    { sequence: '4', payload: { toTaskIndex: 3, overallDeadline: predecessorDeadline } },
    { sequence: '7', payload: { ...transition, previousOverallDeadline: predecessorDeadline } },
  ];
  const terminalizationEvents = [{ sequence: '6', payload: { taskIndex: 3, taskId: 'M1' } }];
  const proof = { taskIds, transition, runStartedEvents, activationEvents, terminalizationEvents,
    initialOverallDeadline: startDeadline };

  assert.equal(trainingSequenceTransitionBasis(proof).previousDeadline, Date.parse(predecessorDeadline));
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof, terminalizationEvents: [] }),
    { code: 'successor_predecessor_terminalization_missing_or_stale' });
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    terminalizationEvents: [{ sequence: '6', payload: { taskIndex: 3, taskId: 'M3' } }] }),
  { code: 'successor_predecessor_terminalization_missing_or_stale' });
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    activationEvents: activationEvents.map((event) => event.sequence === '7'
      ? { ...event, payload: { ...event.payload, previousOverallDeadline: startDeadline } } : event) }),
  { code: 'successor_previous_deadline_missing_or_stale' });
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    activationEvents: activationEvents.map((event) => event.sequence === '4'
      ? { ...event, payload: { ...event.payload, overallDeadline: undefined } }
      : event.sequence === '7' ? { ...event, payload: { ...event.payload, previousOverallDeadline: startDeadline } } : event) }),
  { code: 'successor_previous_deadline_missing_or_stale' });
});

test('first successor uses the authoritative run-start deadline when the pre-start snapshot is null', () => {
  const taskIds = ['S1', 'S2'];
  const transition = trainingSequenceTransitions(taskIds)[0];
  const deadline = '2026-10-29T00:19:37.332Z';
  const proof = {
    taskIds,
    transition,
    runStartedEvents: [{ sequence: '3', payload: { overallDeadline: deadline } }],
    terminalizationEvents: [{ sequence: '9', payload: { taskIndex: 0, taskId: 'S1' } }],
    activationEvents: [{ sequence: '10', payload: { ...transition, previousOverallDeadline: deadline } }],
    initialOverallDeadline: null,
  };

  assert.equal(trainingSequenceTransitionBasis(proof).previousDeadline, Date.parse(deadline));
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    activationEvents: [{ sequence: '10', payload: { ...transition, previousOverallDeadline: '2026-10-29T00:19:37.333Z' } }] }),
  { code: 'successor_previous_deadline_missing_or_stale' });
});

test('first successor preserves Date milliseconds and rejects stale or malformed supplied deadlines', () => {
  const taskIds = ['S1', 'S2'];
  const transition = trainingSequenceTransitions(taskIds)[0];
  const deadline = '2026-10-29T00:19:37.332Z';
  const proof = {
    taskIds,
    transition,
    runStartedEvents: [{ sequence: '3', payload: { overallDeadline: deadline } }],
    terminalizationEvents: [{ sequence: '9', payload: { taskIndex: 0, taskId: 'S1' } }],
    activationEvents: [{ sequence: '10', payload: { ...transition, previousOverallDeadline: deadline } }],
    initialOverallDeadline: new Date(deadline),
  };

  assert.equal(trainingSequenceTransitionBasis(proof).previousDeadline, Date.parse(deadline));
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    initialOverallDeadline: new Date(Date.parse(deadline) + 1) }),
  { code: 'successor_previous_deadline_missing_or_stale' });
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof, initialOverallDeadline: 'invalid-date' }),
    { code: 'successor_previous_deadline_missing_or_stale' });
  assert.throws(() => trainingSequenceTransitionBasis({ ...proof,
    activationEvents: [{ sequence: '10', payload: { ...transition, previousOverallDeadline: '2026-10-29T00:19:37.333Z' } }] }),
  { code: 'successor_previous_deadline_missing_or_stale' });
});

test('cleanup reports fenced selected-prefix leases when successor proof failed before recording activation', () => {
  const taskIds = ['S1', 'S2'];
  const preparations = [
    { task_index: 0, task_id: 'S1', lease_state: 'fenced' },
    { task_index: 1, task_id: 'S2', lease_state: 'fenced' },
  ];
  const recordedSuccessorActivations = [];

  assert.equal(recordedSuccessorActivations.length, 0);
  assert.equal(trainingCleanupLeasePrefixIsFenced({ mode: 'training', preparations, taskIds }), true);
  assert.equal(trainingCleanupLeasePrefixIsFenced({ mode: 'training', preparations: [
    ...preparations, { task_index: 2, task_id: 'S4', lease_state: 'fenced' },
  ], taskIds }), false);
  assert.equal(trainingCleanupLeasePrefixIsFenced({ mode: 'training', preparations: [
    { ...preparations[0], task_id: 'S2' }, preparations[1],
  ], taskIds }), false);
  assert.equal(trainingCleanupLeasePrefixIsFenced({ mode: 'training', preparations: [
    preparations[0], { ...preparations[1], lease_state: 'leased' },
  ], taskIds }), false);
  // Ranked retains the old contiguous-index/fenced-state predicate without a new count or task-ID check.
  assert.equal(trainingCleanupLeasePrefixIsFenced({ mode: 'ranked', taskIds: ['S1'], preparations: [
    { task_index: 0, lease_state: 'fenced' }, { task_index: 1, lease_state: 'fenced' },
  ] }), true);
});

test('verifier activation result shape satisfies the all-open chain consumer', () => {
  const taskIds = [...OPEN_TASK_IDS];
  const transition = trainingSequenceTransitions(taskIds)[0];
  const activationResult = trainingSuccessorActivationResult({ transition, proof: {
    taskIndex: transition.toTaskIndex, taskId: transition.toTaskId, activationEventSequence: '9',
  } });

  assert.deepEqual({ fromTaskIndex: activationResult.fromTaskIndex, fromTaskId: activationResult.fromTaskId,
    toTaskIndex: activationResult.toTaskIndex, toTaskId: activationResult.toTaskId,
    taskIndex: activationResult.taskIndex, taskId: activationResult.taskId }, {
    fromTaskIndex: 0, fromTaskId: 'S1', toTaskIndex: 1, toTaskId: 'S2', taskIndex: 1, taskId: 'S2',
  });
  assert.equal(trainingSuccessorActivationChainMatches(['S1', 'S2'], [activationResult]), true);
  assert.equal(trainingSuccessorActivationChainMatches(taskIds, [activationResult]), false);
  const completeProofs = trainingSequenceTransitions(taskIds).map((edge) => trainingSuccessorActivationResult({ transition: edge,
    proof: { taskIndex: edge.toTaskIndex, taskId: edge.toTaskId, activationEventSequence: String(edge.toTaskIndex + 8) } }));
  assert.equal(trainingSuccessorActivationChainMatches(taskIds, completeProofs), true);
  assert.equal(trainingSuccessorActivationChainMatches(taskIds, completeProofs.map((entry, index) => index === 0
    ? { ...entry, toTaskId: undefined } : entry)), false);
});
