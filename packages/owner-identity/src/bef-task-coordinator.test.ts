import assert from 'node:assert/strict';
import test from 'node:test';
import postgres from 'postgres';
import { activeTaskNeedsCancellation, activeTaskNeedsCancellationAfterRecovery, handoffCommittedSuccessor, isResumablePreDispatchPreparation,
  isBoundedSuccessorWindowFailure, isValidSuccessorLocator, leaseGuardedPreparedTaskStartPort,
  predecessorFinishedBeforeOriginalDeadline, successorFailureCancellationReason, parseLocalBefTaskCoordinatorConfig,
  PostgresLocalCoordinatorLease, taskIndexFromFenceResult, cleanupFailedLocalBefTaskCoordinatorStartup,
  type CoordinatorReservedSql } from './bef-task-coordinator.js';
import type { PreparedTaskStartPort, TaskPreparationRecord } from './task-preparation.js';
import { sha256CanonicalTaskJson } from './task-release.js';

const policy = {
  manifestSha256: 'a'.repeat(64),
  scheme: 'exact',
  network: 'eip155:8453',
  asset: `0x${'b'.repeat(40)}`,
  assetTransferMethod: 'eip3009',
  eip712Domain: { name: 'USD Coin', version: '2' },
  maxTimeoutSeconds: 60,
  sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' },
  localAnvil: {
    identity: 'private-anvil-fork', chainId: 8453, anvilVersion: '1.8.6',
    executionNetwork: 'ethereum', hardFork: 'prague', forkBlockNumber: '0x1234', forkBlockHash: `0x${'c'.repeat(64)}`,
  },
  resources: [{ resourceId: 'dataset-a', resourceSha256: 'd'.repeat(64), contentType: 'application/json',
    offers: [{ id: 'canonical', amount: '100000' }] }],
};

test('local coordinator config accepts only a pinned private fork and local BEF endpoints', () => {
  const parsed = parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1',
    adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'http://bef-api:18545',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: policy }],
  });
  assert.equal(parsed.environments[0]?.envId, 'bef-env-a');
  assert.equal(parsed.observationPipeline, undefined, 'legacy local config does not enable automatic grading');
  const observationPipeline = { schemaVersion: 'local-bef-training-observation/v1',
    database: { host: 'host.docker.internal', port: 55432, database: 'bef' },
    passwordFile: '/run/secrets/bef_database_observer_password' };
  const observed = parseLocalBefTaskCoordinatorConfig({ ...parsed, observationPipeline });
  assert.equal(observed.observationPipeline?.database.database, 'bef');
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({ ...parsed,
    observationPipeline: { ...observationPipeline, database: { ...observationPipeline.database, host: '8.8.8.8' } } }),
  /local_bef_observer_database_must_be_private/);
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({ ...parsed,
    observationPipeline: { ...observationPipeline, passwordFile: '/tmp/unrelated-secret' } }));
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1', adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'https://external.example',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: policy }],
  }), /local_bef_coordinator_url/);
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1', adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'http://bef-api:18545',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: { ...policy, network: 'eip155:1' } }],
  }));
});

test('local coordinator advisory lease binds to one backend and fails closed when its lock proof disappears', async () => {
  let released = 0;
  let ended = 0;
  let held = true;
  const connection: CoordinatorReservedSql = {
    async unsafe(query) {
      if (query.includes('pg_try_advisory_lock')) return [{ acquired: true, backend_pid: 913 }];
      if (query.includes('pg_locks')) return [{ backend_pid: 913, held }];
      return [{ unlocked: true }];
    },
    release() { released += 1; },
  };
  const client = { async reserve() { return connection; }, async end() { ended += 1; } };
  const lease = new PostgresLocalCoordinatorLease(client as never);
  assert.equal(await lease.acquire(), true);
  assert.equal(lease.ownsLease(), true);
  await lease.assertHeld();
  held = false;
  await assert.rejects(lease.assertHeld(), /lease_lost/);
  assert.equal(lease.ownsLease(), false);
  assert.equal(released, 1);
  await lease.stop();
  assert.equal(ended, 1);
});

test('local coordinator does not start when another worker already holds the singleton lock', async () => {
  let released = 0;
  let ended = 0;
  const connection: CoordinatorReservedSql = {
    async unsafe(query) {
      if (query.includes('pg_try_advisory_lock')) return [{ acquired: false, backend_pid: 914 }];
      return [];
    },
    release() { released += 1; },
  };
  const lease = new PostgresLocalCoordinatorLease({ async reserve() { return connection; }, async end() { ended += 1; } } as never);
  assert.equal(await lease.acquire(), false);
  assert.equal(lease.ownsLease(), false);
  assert.equal(released, 1);
  assert.equal(ended, 1);
});

test('failed coordinator startup stops the dedicated lease before closing the shared database client', async () => {
  const order: string[] = [];
  const cleanupError = new Error('lease teardown failed');
  const errors = await cleanupFailedLocalBefTaskCoordinatorStartup({
    async stop() { order.push('coordinator-stop'); throw cleanupError; },
  }, async () => { order.push('database-close'); });
  assert.deepEqual(order, ['coordinator-stop', 'database-close']);
  assert.deepEqual(errors, [cleanupError]);
});

test('successor locator admits only bounded non-final predecessor identities', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const claimId = '20000000-0000-4000-8000-000000000002';
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'training' }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'ranked' }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'evaluation' }), false);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 10, claim_id: claimId }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 11, claim_id: claimId }), false);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0.5, claim_id: claimId }), false);
  assert.equal(isValidSuccessorLocator({ run_id: 'bad', predecessor_task_index: 0, claim_id: claimId }), false);
});

test('restart recovery resumes only the exact leased never-dispatched preparation', () => {
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'preparing', dispatch_status: null }), true);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'preparing', dispatch_status: 'dispatching' }), false);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'ready', dispatch_status: 'completed' }), false);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'fenced', observation_status: 'preparing', dispatch_status: null }), false);
});

test('only explicit saved successor-policy expiry failures use the no-intent cancellation path', () => {
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_WINDOW_EXPIRED'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_TIMEOUT'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_OVERALL_TIME_EXHAUSTED'), false);
  assert.equal(isBoundedSuccessorWindowFailure('RUN_TASK_PREDECESSOR_NOT_KNOWN'), false);
  assert.equal(isBoundedSuccessorWindowFailure(null), false);
  assert.equal(predecessorFinishedBeforeOriginalDeadline({
    finishedAt: '2026-10-28T00:00:00.000Z', overallDeadline: '2026-10-28T00:05:00.000Z',
  }), true);
  assert.equal(predecessorFinishedBeforeOriginalDeadline({
    finishedAt: '2026-10-28T00:05:00.000Z', overallDeadline: '2026-10-28T00:05:00.000Z',
  }), false);
  assert.equal(predecessorFinishedBeforeOriginalDeadline(null), null);
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_WINDOW_EXPIRED', false, true),
    'coordinator_preparation_failed');
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE', false, true),
    'coordinator_preparation_failed');
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_WINDOW_EXPIRED', false, false), null);
  assert.equal(successorFailureCancellationReason('SUCCESSOR_OVERALL_TIME_EXHAUSTED', false, true), null);
  assert.equal(successorFailureCancellationReason('RUN_TASK_PREDECESSOR_NOT_KNOWN', false, true), null);
  assert.equal(successorFailureCancellationReason('RUN_TASK_PREDECESSOR_NOT_KNOWN', true, null),
    'coordinator_interrupted_preparation');
});

test('lost RAM selection and cancellation cleanup use the exact active task index', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const attached = new Map([[`${runId}:0`, {}], [`${runId}:2`, {}]]);
  assert.equal(activeTaskNeedsCancellation(runId, 2, attached), false);
  assert.equal(activeTaskNeedsCancellation(runId, 1, attached), true);
  assert.equal(activeTaskNeedsCancellation(runId, 12, attached), true);
  assert.equal(taskIndexFromFenceResult({ fenced: true, taskPreparation: {
    taskIndex: 2, preparationId: '30000000-0000-4000-8000-000000000003', generationId: null,
  } }), 2);
  assert.equal(taskIndexFromFenceResult({ fenced: true, taskPreparation: {
    taskIndex: 0, preparationId: '30000000-0000-4000-8000-000000000003', generationId: null,
  } }), 0);
  assert.equal(taskIndexFromFenceResult({ fenced: false }), null);
});

function fencedKnownClosedRecoveryRow(): Record<string, unknown> {
  const runId = '10000000-0000-4000-8000-000000000001';
  const ownerId = '11000000-0000-4000-8000-000000000011';
  const agentId = '12000000-0000-4000-8000-000000000012';
  const closureId = '13000000-0000-4000-8000-000000000013';
  const preparationId = '14000000-0000-4000-8000-000000000014';
  const leaseId = '15000000-0000-4000-8000-000000000015';
  const generationId = '16000000-0000-4000-8000-000000000016';
  const environmentId = 'bef-env-a';
  const releaseIdentity = 'synthetic-release/v1';
  const releaseManifestHash = 'a'.repeat(64);
  const environmentManifestHash = 'b'.repeat(64);
  const applicationSourceHash = 'c'.repeat(64);
  const executionIdentityHash = 'd'.repeat(64);
  const initialStateSha256 = 'e'.repeat(64);
  const caseId = 's1-case';
  const caseHash = 'f'.repeat(64);
  const rubricHash = '1'.repeat(64);
  const closurePayloadHash = '2'.repeat(64);
  const binding = { runId, ownerId, agentId, environmentId, releaseIdentity, manifestHash: releaseManifestHash,
    caseId, caseHash, rubricHash, taskId: 'S1' };
  const closure = { closureId, operationId: 'owner-close-op', payloadHash: closurePayloadHash,
    reason: 'agent_finish', actionCutoffSequence: 0, reconciledActionSequence: 0 };
  const execution = { preparationId, leaseId, generationId, environmentManifestHash, applicationSourceHash,
    executionIdentityHash, initialStateSha256 };
  const observations = { schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 1,
    captureEvidence: { path: 'capture.json', sha256: '3'.repeat(64) } };
  const bundle = { schemaVersion: 'bts-task-observation-bundle/v1', binding, closure, execution,
    cutoff: { observationSequence: 1, status: 'authoritative', evidence: observations.captureEvidence }, observations };
  const result = { status: 'known', taskId: 'S1', outcome: 'passed', mandatoryViolation: null };
  const input = { taskCase: { taskId: 'S1', mode: 'training', caseId, caseHash, rubricHash },
    release: { releaseIdentity, manifestHash: releaseManifestHash },
    run: { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0,
      observationCutoffSequence: 1, cutoffStatus: 'authoritative', cutoffEvidence: observations.captureEvidence }, observations };
  const expectedEvent = { taskIndex: 0, taskId: 'S1', closureId, releaseIdentity, manifestHash: releaseManifestHash,
    inputHash: sha256CanonicalTaskJson(input), resultHash: sha256CanonicalTaskJson(result), evaluatorSourceHash: '4'.repeat(64) };
  return {
    run_id: runId, owner_id: ownerId, agent_id: agentId, run_mode: 'training', run_status: 'running',
    task_index: 0, task_id: 'S1', task_status: 'active', closure_status: 'closed', closure_id: closureId,
    accepted_action_sequence: '0', action_cutoff_sequence: '0', reconciled_action_sequence: '0',
    release_identity: releaseIdentity, release_manifest_hash: releaseManifestHash,
    closure_operation_id: 'owner-close-op', closure_payload_hash: closurePayloadHash, closure_reason: 'agent_finish',
    preparation_id: preparationId, preparation_run_id: runId, preparation_task_index: 0, preparation_task_id: 'S1',
    preparation_release_identity: releaseIdentity, preparation_manifest_hash: releaseManifestHash,
    preparation_case_id: caseId, preparation_case_hash: caseHash, preparation_initial_state_sha256: initialStateSha256,
    preparation_environment_manifest_sha256: environmentManifestHash,
    preparation_application_source_hash: applicationSourceHash, preparation_execution_identity_hash: executionIdentityHash,
    preparation_lease_id: leaseId, preparation_environment_id: environmentId,
    lease_preparation_id: preparationId, lease_id: leaseId, lease_state: 'fenced',
    lease_fence_evidence: { confirmed: true, preparationId, leaseId, environmentId, generationId },
    observation_status: 'fenced', observed_generation_id: generationId, preparation_observation_generation_id: generationId,
    registered_generation_id: generationId, registered_environment_id: environmentId,
    binding_run_id: runId, binding_task_index: 0, binding_environment_id: environmentId, binding_generation_id: generationId,
    binding_manifest_hash: environmentManifestHash, binding_source_hash: applicationSourceHash,
    closure_run_id: runId, closure_task_index: 0, journal_closure_id: closureId, journal_cutoff_sequence: '0',
    journal_payload_hash: closurePayloadHash, journal_reason: 'agent_finish', journal_operation_id: 'owner-close-op',
    journal_owner_id: ownerId, journal_agent_id: agentId,
    bundle_run_id: runId, bundle_task_index: 0, bundle_owner_id: ownerId, bundle_agent_id: agentId, bundle_task_id: 'S1',
    bundle_closure_id: closureId, bundle_preparation_id: preparationId, bundle_lease_id: leaseId,
    bundle_closure_operation_id: 'owner-close-op', bundle_closure_payload_hash: closurePayloadHash,
    bundle_closure_reason: 'agent_finish', bundle_rubric_hash: rubricHash, bundle_initial_state_sha256: initialStateSha256,
    bundle_environment_id: environmentId, bundle_generation_id: generationId,
    bundle_release_identity: releaseIdentity, bundle_release_manifest_hash: releaseManifestHash,
    bundle_case_id: caseId, bundle_case_hash: caseHash,
    bundle_environment_manifest_hash: environmentManifestHash, bundle_application_source_hash: applicationSourceHash,
    bundle_execution_identity_hash: executionIdentityHash, bundle_cutoff_sequence: '0', bundle_reconciled_sequence: '0',
    bundle_hash: sha256CanonicalTaskJson(bundle), bundle_json: bundle,
    evaluation_run_id: runId, evaluation_task_index: 0, evaluation_closure_id: closureId, evaluation_task_id: 'S1',
    evaluation_release_identity: releaseIdentity, evaluation_manifest_hash: releaseManifestHash,
    evaluation_case_hash: caseHash, evaluation_rubric_hash: rubricHash,
    evaluation_input_hash: sha256CanonicalTaskJson(input), evaluation_result_hash: sha256CanonicalTaskJson(result),
    evaluation_evaluator_source_hash: expectedEvent.evaluatorSourceHash, evaluation_input_json: input, evaluation_result_json: result,
    evaluation_event_count: '1', evaluation_event_source: 'coordinator', evaluation_event_payload_hash: sha256CanonicalTaskJson(expectedEvent),
    evaluation_event_payload_json: expectedEvent, terminalization_event_count: '0',
  };
}

test('missing RAM does not cancel an exact fenced, closed, known task awaiting normal terminalization', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const attached = new Map<string, unknown>();
  const recovery = fencedKnownClosedRecoveryRow();
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, recovery), false);

  // A live open task, or a fenced row for a different generation, does not qualify for this gap.
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, closure_status: 'open', action_cutoff_sequence: null,
  }), true);
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, binding_generation_id: '17000000-0000-4000-8000-000000000017',
  }), true);
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, lease_state: 'leased',
  }), true);
});

test('prepared start port checks coordinator lease before and after its delegated work', async () => {
  const order: string[] = [];
  let checks = 0;
  const base = {
    async readCandidatePreparationId() { order.push('read'); return '40000000-0000-4000-8000-000000000004'; },
    async assertReadyInTransaction() { order.push('ready'); return {} as TaskPreparationRecord; },
    hasUsableStartSession() { return true; },
    async attachStartedSession() { order.push('attach'); },
  } as unknown as PreparedTaskStartPort;
  const guarded = leaseGuardedPreparedTaskStartPort(base, async () => { checks += 1; order.push(`lease-${checks}`); });
  const target = { runId: '10000000-0000-4000-8000-000000000001', taskIndex: 1, claimId: '20000000-0000-4000-8000-000000000002' };
  assert.equal(await guarded.readCandidatePreparationId(target), '40000000-0000-4000-8000-000000000004');
  assert.deepEqual(order, ['lease-1', 'read', 'lease-2']);
  order.length = 0;
  await guarded.attachStartedSession({} as TaskPreparationRecord, new Date(Date.now() + 60_000).toISOString());
  assert.deepEqual(order, ['lease-3', 'attach', 'lease-4']);

  let calls = 0;
  order.length = 0;
  const lostAfterRead = leaseGuardedPreparedTaskStartPort(base, async () => {
    calls += 1;
    if (calls === 2) throw new Error('local_bef_coordinator_lease_lost');
  });
  await assert.rejects(lostAfterRead.readCandidatePreparationId(target), /lease_lost/);
  assert.deepEqual(order, ['read']);
});

test('post-commit successor attach failure requests exact task cancellation, while lease loss leaves recovery to the next owner', async () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const preparation = { intent: { runId, taskIndex: 2 } } as unknown as TaskPreparationRecord;
  const cancellations: Array<{ runId: string; taskIndex: number; reason: string }> = [];
  const failedAttach = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: false, preparation, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() {}, async attach() { throw new Error('session_attach_failed'); },
    async cancelAndFence(cancelRunId, taskIndex, reason) { cancellations.push({ runId: cancelRunId, taskIndex, reason }); },
  });
  assert.equal(failedAttach, 'cancelled');
  assert.deepEqual(cancellations, [{ runId, taskIndex: 2, reason: 'coordinator_executor_session_lost' }]);

  let attached = 0;
  let cancelled = 0;
  const lostLease = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: false, preparation, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() { throw new Error('local_bef_coordinator_lease_lost'); },
    async attach() { attached += 1; }, async cancelAndFence() { cancelled += 1; },
  });
  assert.equal(lostLease, 'lease_lost');
  assert.equal(attached, 0);
  assert.equal(cancelled, 0);

  const replayWithoutRam = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: true, preparation: null, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() {}, async attach() { attached += 1; },
    async cancelAndFence(_runId, taskIndex, reason) { cancellations.push({ runId, taskIndex, reason }); },
  });
  assert.equal(replayWithoutRam, 'cancelled');
  assert.equal(attached, 0);
  assert.equal(cancellations.at(-1)?.taskIndex, 2);
});

test('Postgres advisory lease contends and becomes available after its owning pool closes', {
  skip: process.env.OID_COORDINATOR_LEASE_INTEGRATION !== 'true',
}, async () => {
  const databaseUrl = process.env.OID_DATABASE_URL;
  assert.ok(databaseUrl, 'the explicit owner PostgreSQL integration run must provide OID_DATABASE_URL');
  const first = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  const contender = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  const recovered = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  try {
    assert.equal(await first.acquire(), true);
    await first.assertHeld();
    assert.equal(await contender.acquire(), false);
    await first.stop();
    assert.equal(await recovered.acquire(), true);
    await recovered.assertHeld();
  } finally {
    await Promise.all([first.stop(), contender.stop(), recovered.stop()]);
  }
});
