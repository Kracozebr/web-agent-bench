import assert from 'node:assert/strict';
import test from 'node:test';
import { OPEN_TASK_IDS, normalizeTrainingSequenceTaskIds, quoteTrainingSelectionUnits, trainingSequenceGrantAmountUnits,
  trainingCleanupLeasePrefixIsFenced, trainingSequenceTransitionBasis, trainingSequenceTransitions,
  trainingSuccessorActivationChainMatches, trainingSuccessorActivationResult } from './genuine-s1-cases.mjs';

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
