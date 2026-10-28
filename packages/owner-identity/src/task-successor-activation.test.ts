import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { EvaluateTaskInput } from './task-evaluator.js';
import { SUCCESSOR_PREPARATION_POLICY_VERSION } from './run-service.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import { addFixture, evidence } from './task-run-completion.test-fixture.js';
import { finalizeKnownTrainingTask } from './task-run-completion.js';
import { activatePreparedTrainingSuccessor } from './task-successor-activation.js';
import {
  createPreparedSuccessorTaskStartPort,
  prepareSuccessorTaskExecution,
  type PreparedTaskStartPort,
  type SuccessorTaskPreparationDependencies,
  type TaskPreparationAdapter,
  type TaskPreparationRecord,
} from './task-preparation.js';

const enabled = process.env.OID_TASK_SUCCESSOR_ACTIVATION_PG_TEST === '1';
const POLICY = SUCCESSOR_PREPARATION_POLICY_VERSION;

type Fixture = Awaited<ReturnType<typeof addFixture>>;

async function insertSyntheticSuccessorPreparation(client: ReturnType<typeof postgres>, fixture: Fixture, options: {
  observationStatus?: 'preparing' | 'ready';
  reportedGenerationId?: string;
  delayMilliseconds?: number;
} = {}) {
  const taskCase = fixture.record.manifest.cases.training.find((entry) => entry.taskId === 'S2');
  assert.ok(taskCase, 'the synthetic sealed training release contains S2');
  const preparationId = randomUUID();
  const leaseId = randomUUID();
  const generationId = randomUUID();
  const environmentId = `synthetic-successor-${randomUUID().slice(0, 8)}`;
  const fixtureEvidence = evidence(`${fixture.runId}-successor-fixture`);
  const baselineEvidence = evidence(`${fixture.runId}-successor-baseline`);
  const createdAt = new Date().toISOString();
  await client`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
      release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
      environment_manifest_sha256,application_source_hash)
    VALUES(${preparationId},${fixture.runId},1,${fixture.claimId},${leaseId},${environmentId},${fixture.record.releaseIdentity},
      ${fixture.record.manifestHash},'S2',${taskCase.caseId},${taskCase.caseHash},${taskCase.initialState.stateSha256},
      ${taskCase.executionIdentityHash},${fixture.record.manifest.executionIdentity.environmentManifestSha256},
      ${fixture.record.manifest.executionIdentity.x402ServiceSha256})`;
  await client`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id)
    VALUES(${leaseId},${preparationId},${environmentId})`;
  await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status)
    VALUES(${preparationId},1,'preparing')`;
  if ((options.observationStatus ?? 'ready') === 'ready') {
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
        baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES(${preparationId},2,'ready',${generationId},'synthetic-successor-participant',
        '0x2222222222222222222222222222222222222222',${taskCase.initialState.stateSha256},
        ${JSON.stringify(fixtureEvidence)}::jsonb,${JSON.stringify(baselineEvidence)}::jsonb)`;
  }
  const reportedGenerationId = options.reportedGenerationId ?? generationId;
  const record: TaskPreparationRecord = {
    intent: {
      preparationId, runId: fixture.runId, taskIndex: 1, claimId: fixture.claimId, leaseId, environmentId,
      releaseIdentity: fixture.record.releaseIdentity, manifestHash: fixture.record.manifestHash, taskId: 'S2',
      caseId: taskCase.caseId, caseHash: taskCase.caseHash, initialStateSha256: taskCase.initialState.stateSha256,
      executionIdentityHash: taskCase.executionIdentityHash,
      environmentManifestSha256: fixture.record.manifest.executionIdentity.environmentManifestSha256,
      applicationSourceHash: fixture.record.manifest.executionIdentity.x402ServiceSha256, createdAt,
    },
    observation: {
      revision: (options.observationStatus ?? 'ready') === 'ready' ? 2 : 1,
      status: options.observationStatus ?? 'ready',
      generationId: (options.observationStatus ?? 'ready') === 'ready' ? reportedGenerationId : null,
      participantId: (options.observationStatus ?? 'ready') === 'ready' ? 'synthetic-successor-participant' : null,
      payerAddress: (options.observationStatus ?? 'ready') === 'ready' ? '0x2222222222222222222222222222222222222222' : null,
      baselineStateSha256: (options.observationStatus ?? 'ready') === 'ready' ? taskCase.initialState.stateSha256 : null,
      fixtureEvidence: (options.observationStatus ?? 'ready') === 'ready' ? fixtureEvidence : null,
      baselineEvidence: (options.observationStatus ?? 'ready') === 'ready' ? baselineEvidence : null,
      reasonCode: null, createdAt,
    },
    leaseStatus: 'leased', dispatchStatus: (options.observationStatus ?? 'ready') === 'ready' ? 'completed' : 'dispatching',
  };
  const port: PreparedTaskStartPort = {
    async readCandidatePreparationId(target) {
      assert.deepEqual(target, { runId: fixture.runId, taskIndex: 1, claimId: fixture.claimId });
      return preparationId;
    },
    async assertReadyInTransaction(_tx, target, candidateId, minimumValidUntil) {
      assert.deepEqual(target, { runId: fixture.runId, taskIndex: 1, claimId: fixture.claimId });
      assert.equal(candidateId, preparationId);
      assert.ok(Number.isFinite(Date.parse(minimumValidUntil)));
      if (options.delayMilliseconds) await new Promise((resolve) => setTimeout(resolve, options.delayMilliseconds));
      return structuredClone(record);
    },
    hasUsableStartSession(_preparation, minimumValidUntil) { return Number.isFinite(Date.parse(minimumValidUntil)); },
    async assertLeaseHeld() {},
    async attachStartedSession() {},
  };
  return { preparationId, generationId, port };
}

async function prepareThroughRealSuccessorPort(
  db: OwnerDatabase,
  releaseSource: TaskReleaseQuerySource,
  predecessorEvidenceSource: SuccessorTaskPreparationDependencies['predecessorEvidenceSource'],
  fixture: Fixture,
): Promise<PreparedTaskStartPort> {
  // This adapter and its evidence are test-only synthetic values. It exercises
  // real persistence and port locks; it does not start or prove an executor.
  const preparationAdapter: TaskPreparationAdapter = {
    async prepare({ intent }) {
      return {
        status: 'prepared',
        result: {
          environmentId: intent.environmentId, generationId: randomUUID(), manifestHash: intent.manifestHash,
          applicationSourceHash: intent.applicationSourceHash,
          environmentManifestSha256: intent.environmentManifestSha256,
          initialStateSha256: intent.initialStateSha256,
          participantId: 'synthetic-successor-participant', payerAddress: '0x2222222222222222222222222222222222222222',
          fixtureEvidence: evidence(`${fixture.runId}-actual-port-fixture`),
          baselineEvidence: evidence(`${fixture.runId}-actual-port-baseline`),
        },
      };
    },
    async reconcile({ generationId }) { return { status: 'unknown', generationId, reasonCode: 'adapter_outcome_unknown' }; },
    async fence({ intent, generationId }) {
      return { confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
        environmentId: intent.environmentId, generationId, evidence: evidence(`${fixture.runId}-synthetic-fence`) };
    },
    hasUsableStartSession() { return true; },
  };
  const deps: SuccessorTaskPreparationDependencies = {
    db, releaseSource, predecessorEvidenceSource, preparationAdapter,
    environmentSelector: { async selectEnvironment({ runId }) { return `synthetic-successor-${runId.slice(0, 8)}`; } },
  };
  await prepareSuccessorTaskExecution(deps, { runId: fixture.runId, taskIndex: 1, claimId: fixture.claimId });
  return createPreparedSuccessorTaskStartPort(deps, async () => {});
}

test('private local synthetic training successor activation is atomic, bounded, and replayable', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'the Docker runtime must provide its isolated owner DB URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'this fixture must run inside the owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const databaseName = `oid_successor_${randomUUID().replaceAll('-', '')}`;
  const testUrl = new URL(sourceUrlValue);
  testUrl.pathname = `/${databaseName}`;
  const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
  const client = postgres(testUrl.toString(), { max: 8, connect_timeout: 10 });
  const db = drizzle(client) as unknown as OwnerDatabase;
  try {
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);
    const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], {
      cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: testUrl.toString() }, encoding: 'utf8',
    });
    assert.equal(migration.status, 0, 'the isolated successor acceptance database must migrate successfully');

    const fixtures = [
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 1 }),
      await addFixture(client, { multiTask: true, overallDeadlinePast: true,
        successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180,
        verifiedNativeReserveViolation: true }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180,
        verifiedNativeReserveViolation: true, contradictoryMandatoryViolationResult: 'partial' }),
      await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180,
        verifiedNativeReserveViolation: true, contradictoryMandatoryViolationResult: 'passed' }),
    ];
    const source = { async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord(identity: string, manifest: string) {
      return fixtures.find((fixture) => fixture.record.releaseIdentity === identity && fixture.record.manifestHash === manifest)?.record as never ?? null;
    } } satisfies TaskReleaseQuerySource;
    const completionDeps = {
      db, taskReleaseSource: source,
      evidenceSource: { async load(input: { runId: string; taskIndex: number; closureId: string }) {
        return structuredClone(fixtures.find((fixture) => fixture.runId === input.runId)?.evaluationInput ?? null) as EvaluateTaskInput | null;
      } },
    };
    const activate = (fixture: Fixture, port: PreparedTaskStartPort) => activatePreparedTrainingSuccessor(
      { ...completionDeps, preparedTaskStart: port }, { runId: fixture.runId, predecessorTaskIndex: 0 },
    );
    const failCode = (code: string) => (error: { code?: string }) => error.code === code;

    // First-task charging and claim/slot identities survive one successor activation.
    const happy = fixtures[0]!;
    const before = await client`SELECT r.started_at,r.overall_deadline,r.status,c.claim_id,c.status AS claim_status,
        s.claim_id AS slot_claim_id,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=r.id) AS reservations,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reserved_units,
        (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=r.id AND state='charged') AS charged_holds,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS held_units,
        (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluations
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${happy.runId}`;
    const predecessor = await finalizeKnownTrainingTask(completionDeps, { runId: happy.runId, taskIndex: 0 });
    assert.equal(predecessor.replayed, false);
    const realPort = await prepareThroughRealSuccessorPort(db, source, completionDeps.evidenceSource, happy);
    const activation = await activate(happy, realPort);
    assert.equal(activation.replayed, false);
    assert.equal(activation.toTaskId, 'S2');
    assert.ok(activation.preparation, 'the internal caller receives the exact secret-free preparation record');
    const after = await client`SELECT r.started_at,r.overall_deadline,r.status,c.claim_id,c.status AS claim_status,
        s.claim_id AS slot_claim_id,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=r.id) AS reservations,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reserved_units,
        (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=r.id AND state='charged') AS charged_holds,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS held_units,
        (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluations,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations,
        (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings,
        (SELECT status FROM oid_run_task WHERE run_id=r.id AND task_index=1) AS successor_status
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${happy.runId}`;
    assert.equal(new Date(String(after[0]?.started_at)).toISOString(), new Date(String(before[0]?.started_at)).toISOString());
    assert.equal(after[0]?.status, 'running');
    assert.equal(after[0]?.claim_id, before[0]?.claim_id);
    assert.equal(after[0]?.claim_status, 'claimed');
    assert.equal(after[0]?.slot_claim_id, before[0]?.slot_claim_id);
    assert.equal(after[0]?.slot_state, 'running');
    assert.equal(after[0]?.reservations, before[0]?.reservations);
    assert.equal(after[0]?.reserved_units, before[0]?.reserved_units);
    assert.equal(after[0]?.charged_holds, before[0]?.charged_holds);
    assert.equal(after[0]?.held_units, before[0]?.held_units);
    assert.equal(after[0]?.evaluations, before[0]?.evaluations, 'activation does not invent a successor result');
    assert.equal(after[0]?.activations, 1);
    assert.equal(after[0]?.bindings, 2);
    assert.equal(after[0]?.successor_status, 'active');
    assert.ok(activation.preparationIntervalMilliseconds >= 0);
    assert.equal(Date.parse(activation.overallDeadline), Date.parse(activation.previousOverallDeadline) + activation.preparationIntervalMilliseconds);
    assert.ok(Date.parse(activation.taskDeadline) > Date.parse(activation.activatedAt));

    // Even after the successor cutoff closes while it awaits its own grade, replay returns the same activation.
    const successorClosureId = randomUUID();
    const successorClosureHash = 'a'.repeat(64);
    await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,action_cutoff_sequence,
        actor_kind,owner_id,agent_id)
      VALUES(${successorClosureId},${happy.runId},1,NULL,${successorClosureHash},'agent_finish',0,'coordinator',${happy.ownerId},${happy.agentId})`;
    await client`UPDATE oid_run_task SET closure_status='closed',closure_id=${successorClosureId},action_cutoff_sequence=0,
        closure_reason='agent_finish',closure_payload_hash=${successorClosureHash},closed_at=clock_timestamp()
      WHERE run_id=${happy.runId} AND task_index=1 AND status='active'`;
    const replay = await activate(happy, realPort);
    assert.equal(replay.replayed, true);
    assert.equal(replay.preparation, null);
    assert.equal(replay.activatedAt, activation.activatedAt);
    assert.equal(replay.overallDeadline, activation.overallDeadline);
    assert.equal(replay.taskDeadline, activation.taskDeadline);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_run_event WHERE run_id=${happy.runId} AND event_type='task.activated'`)[0]?.count, 1);

    const concurrent = fixtures[7]!;
    const concurrentReady = await insertSyntheticSuccessorPreparation(client, concurrent);
    await finalizeKnownTrainingTask(completionDeps, { runId: concurrent.runId, taskIndex: 0 });
    const simultaneous = await Promise.all([activate(concurrent, concurrentReady.port), activate(concurrent, concurrentReady.port)]);
    assert.deepEqual(simultaneous.map((item) => item.replayed).sort(), [false, true]);
    assert.equal(simultaneous[0]?.activatedAt, simultaneous[1]?.activatedAt);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_run_event WHERE run_id=${concurrent.runId} AND event_type='task.activated'`)[0]?.count, 1);
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_task_execution_binding WHERE run_id=${concurrent.runId}`)[0]?.count, 2);

    // A preparation delay cannot exceed the policy bound just because readiness started in time.
    const timeout = fixtures[1]!;
    const slow = await insertSyntheticSuccessorPreparation(client, timeout, { delayMilliseconds: 1_200 });
    await finalizeKnownTrainingTask(completionDeps, { runId: timeout.runId, taskIndex: 0 });
    const beforeTimeout = await client`SELECT r.overall_deadline,t.status AS successor_status,
        (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=1 WHERE r.id=${timeout.runId}`;
    await assert.rejects(activate(timeout, slow.port), failCode('SUCCESSOR_PREPARATION_TIMEOUT'));
    const afterTimeout = await client`SELECT r.overall_deadline,t.status AS successor_status,
        (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=1 WHERE r.id=${timeout.runId}`;
    assert.deepEqual(afterTimeout[0], beforeTimeout[0], 'the late readiness failure leaves no activation side effect');

    // A predecessor already completed at/after the original deadline cannot gain new execution time.
    const exhausted = fixtures[2]!;
    const exhaustedReady = await insertSyntheticSuccessorPreparation(client, exhausted);
    await finalizeKnownTrainingTask(completionDeps, { runId: exhausted.runId, taskIndex: 0 });
    await assert.rejects(activate(exhausted, exhaustedReady.port), failCode('SUCCESSOR_OVERALL_TIME_EXHAUSTED'));
    const exhaustedState = await client`SELECT status,overall_deadline FROM oid_benchmark_run WHERE id=${exhausted.runId}`;
    assert.equal(exhaustedState[0]?.status, 'running');
    assert.equal(new Date(String(exhaustedState[0]?.overall_deadline)).toISOString(), exhausted.overallDeadline);

    // The original deadline may pass during preparation; only the interval from predecessor finish is bounded.
    const crossed = await addFixture(client, { multiTask: true, overallDeadlineSecondsFromNow: 10,
      successorPreparationPolicyVersion: POLICY, successorPreparationTimeoutSeconds: 180 });
    fixtures.push(crossed);
    const crossingFinalized = await finalizeKnownTrainingTask(completionDeps, { runId: crossed.runId, taskIndex: 0 });
    assert.equal(crossingFinalized.replayed, false);
    const crossingClock = await client`SELECT t.finished_at<r.overall_deadline AS predecessor_finished_before_deadline,
        GREATEST(0,ceil(extract(epoch FROM (r.overall_deadline-clock_timestamp()))*1000)::int) AS milliseconds_until_deadline
      FROM oid_run_task t JOIN oid_benchmark_run r ON r.id=t.run_id
      WHERE t.run_id=${crossed.runId} AND t.task_index=0`;
    assert.equal(crossingClock[0]?.predecessor_finished_before_deadline, true,
      'the predecessor must be terminal before the original run deadline');
    const millisecondsUntilDeadline = Number(crossingClock[0]?.milliseconds_until_deadline);
    assert.ok(Number.isSafeInteger(millisecondsUntilDeadline) && millisecondsUntilDeadline >= 1_000,
      'the fixture starts readiness with a reliable finish-before-deadline margin');
    const crossingReady = await insertSyntheticSuccessorPreparation(client, crossed,
      { delayMilliseconds: millisecondsUntilDeadline + 250 });
    const crossing = await activate(crossed, crossingReady.port);
    assert.ok(Date.parse(crossing.activatedAt) > Date.parse(crossed.overallDeadline), 'prep can cross the old deadline');
    assert.ok(crossing.preparationIntervalMilliseconds <= 180_000);
    assert.equal(Date.parse(crossing.overallDeadline), Date.parse(crossing.previousOverallDeadline) + crossing.preparationIntervalMilliseconds);

    // Missing immutable policy, cancellation history, and an unready/foreign generation all fail closed.
    const missingPolicy = fixtures[3]!;
    const missingReady = await insertSyntheticSuccessorPreparation(client, missingPolicy);
    await finalizeKnownTrainingTask(completionDeps, { runId: missingPolicy.runId, taskIndex: 0 });
    await assert.rejects(activate(missingPolicy, missingReady.port), failCode('SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE'));

    const cancelled = fixtures[4]!;
    const cancelledReady = await insertSyntheticSuccessorPreparation(client, cancelled);
    await finalizeKnownTrainingTask(completionDeps, { runId: cancelled.runId, taskIndex: 0 });
    await client`INSERT INTO oid_run_mode_cancellation_outbox(event_id,owner_id,agent_id,mode,policy_revision)
      VALUES(${randomUUID()},${cancelled.ownerId},${cancelled.agentId},'training',2)`;
    await assert.rejects(activate(cancelled, cancelledReady.port), failCode('RUN_CANCELLATION_HISTORY'));

    const unready = fixtures[5]!;
    const unreadyPort = await insertSyntheticSuccessorPreparation(client, unready, { observationStatus: 'preparing' });
    await finalizeKnownTrainingTask(completionDeps, { runId: unready.runId, taskIndex: 0 });
    await assert.rejects(activate(unready, unreadyPort.port), failCode('TASK_PREPARATION_NOT_READY'));

    const foreign = fixtures[6]!;
    const foreignRecord = await insertSyntheticSuccessorPreparation(client, foreign, { reportedGenerationId: randomUUID() });
    await finalizeKnownTrainingTask(completionDeps, { runId: foreign.runId, taskIndex: 0 });
    await assert.rejects(activate(foreign, foreignRecord.port), failCode('TASK_EXECUTION_BINDING_MISMATCH'));
    const foreignState = await client`SELECT t.status,
        (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=t.run_id AND task_index=1) AS bindings,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=t.run_id AND event_type='task.activated') AS activations
      FROM oid_run_task t WHERE t.run_id=${foreign.runId} AND t.task_index=1`;
    assert.deepEqual(foreignState[0], { status: 'queued', bindings: 0, activations: 0 });

    // A canonical evaluator-derived mandatory violation terminalizes S1 at zero while the same
    // charged run proceeds through its normal successor preparation and activation.
    const mandatoryViolation = fixtures[8]!;
    const beforeViolation = await client`SELECT r.started_at,r.overall_deadline,c.claim_id,s.claim_id AS slot_claim_id,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=r.id) AS reservations,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reserved_units,
        (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=r.id AND state='charged') AS charged_holds,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS held_units
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${mandatoryViolation.runId}`;
    const violationResult = await client`SELECT result_json,result_hash FROM oid_run_task_evaluation
      WHERE run_id=${mandatoryViolation.runId} AND task_index=0`;
    assert.equal((violationResult[0]?.result_json as { status?: string; outcome?: string; credit?: { numerator?: string }; mandatoryViolation?: { rule?: string; observationIds?: string[] } }).status, 'known');
    assert.equal((violationResult[0]?.result_json as { outcome?: string }).outcome, 'failed');
    assert.equal((violationResult[0]?.result_json as { credit?: { numerator?: string } }).credit?.numerator, '0');
    assert.equal((violationResult[0]?.result_json as { mandatoryViolation?: { rule?: string } }).mandatoryViolation?.rule, 'native_reserve');
    assert.deepEqual((violationResult[0]?.result_json as { mandatoryViolation?: { observationIds?: string[] } }).mandatoryViolation?.observationIds,
      [`${mandatoryViolation.runId}-final-state`]);
    const terminalizedViolation = await finalizeKnownTrainingTask(completionDeps, { runId: mandatoryViolation.runId, taskIndex: 0 });
    assert.deepEqual({ status: terminalizedViolation.status, replayed: terminalizedViolation.replayed }, { status: 'failed', replayed: false });
    const violationPort = await prepareThroughRealSuccessorPort(db, source, completionDeps.evidenceSource, mandatoryViolation);
    const violationActivation = await activate(mandatoryViolation, violationPort);
    assert.equal(violationActivation.replayed, false);
    assert.equal(violationActivation.fromTaskIndex, 0);
    assert.equal(violationActivation.toTaskIndex, 1);
    const afterViolation = await client`SELECT r.started_at,r.overall_deadline,r.status,c.claim_id,c.status AS claim_status,
        s.claim_id AS slot_claim_id,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=r.id) AS reservations,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reserved_units,
        (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=r.id AND state='charged') AS charged_holds,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS held_units,
        (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluations,
        (SELECT result_hash FROM oid_run_task_evaluation WHERE run_id=r.id AND task_index=0) AS predecessor_result_hash,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.evaluated') AS evaluation_events,
        (SELECT status FROM oid_run_task WHERE run_id=r.id AND task_index=0) AS predecessor_status,
        (SELECT status FROM oid_run_task WHERE run_id=r.id AND task_index=1) AS successor_status,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.terminalized') AS terminalizations,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations,
        (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${mandatoryViolation.runId}`;
    assert.equal(new Date(String(afterViolation[0]?.started_at)).toISOString(), new Date(String(beforeViolation[0]?.started_at)).toISOString());
    assert.equal(afterViolation[0]?.status, 'running');
    assert.equal(afterViolation[0]?.claim_id, beforeViolation[0]?.claim_id);
    assert.equal(afterViolation[0]?.claim_status, 'claimed');
    assert.equal(afterViolation[0]?.slot_claim_id, beforeViolation[0]?.slot_claim_id);
    assert.equal(afterViolation[0]?.slot_state, 'running');
    assert.equal(afterViolation[0]?.reservations, beforeViolation[0]?.reservations);
    assert.equal(afterViolation[0]?.reserved_units, beforeViolation[0]?.reserved_units);
    assert.equal(afterViolation[0]?.charged_holds, beforeViolation[0]?.charged_holds);
    assert.equal(afterViolation[0]?.held_units, beforeViolation[0]?.held_units);
    assert.equal(afterViolation[0]?.evaluations, 1, 'successor activation neither regrades nor inserts another evaluation');
    assert.equal(afterViolation[0]?.predecessor_result_hash, violationResult[0]?.result_hash);
    assert.equal(afterViolation[0]?.evaluation_events, 1);
    assert.equal(afterViolation[0]?.predecessor_status, 'failed');
    assert.equal(afterViolation[0]?.successor_status, 'active');
    assert.equal(afterViolation[0]?.terminalizations, 1);
    assert.equal(afterViolation[0]?.activations, 1);
    assert.equal(afterViolation[0]?.bindings, 2);
    assert.equal(Date.parse(violationActivation.overallDeadline), Date.parse(violationActivation.previousOverallDeadline) +
      violationActivation.preparationIntervalMilliseconds, 'only the successor preparation interval extends the run clock');

    // Outcome/credit contradictions cannot be hidden behind a claimed mandatory violation.
    for (const malformed of [fixtures[9]!, fixtures[10]!]) {
      await finalizeKnownTrainingTask(completionDeps, { runId: malformed.runId, taskIndex: 0 });
      const malformedPrep = await insertSyntheticSuccessorPreparation(client, malformed);
      const stateBefore = await client`SELECT r.overall_deadline,r.status,t.status AS successor_status,
          (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations,
          (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluations
        FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=1 WHERE r.id=${malformed.runId}`;
      await assert.rejects(activate(malformed, malformedPrep.port), failCode('RUN_TASK_EVALUATIONS_UNKNOWN'));
      const stateAfter = await client`SELECT r.overall_deadline,r.status,t.status AS successor_status,
          (SELECT count(*)::int FROM oid_task_execution_binding WHERE run_id=r.id) AS bindings,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.activated') AS activations,
          (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluations
        FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=1 WHERE r.id=${malformed.runId}`;
      assert.deepEqual(stateAfter[0], stateBefore[0], 'contradictory violations leave activation state and persisted evaluations unchanged');
    }
  } finally {
    await client.end();
    await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await admin.end();
  }
});
