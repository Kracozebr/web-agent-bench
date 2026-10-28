import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { BefFenceProof, BefReadOnlyPostgresPort } from './bef-observation-ports.js';
import { taskPreparationPublicPinsSha256 } from './bef-task-preparation.js';
import type { EvaluateTaskInput, PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import type { EvidenceReference, TaskCase } from './task-release.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import { getTaskEvaluatorBuildHash, recordTaskEvaluation } from './task-result-service.js';
import { getTaskPreparation, type TaskPreparationAdapter } from './task-preparation.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { preflightAndSealKnownCandidate, processClosedTrainingTask, supportsObservationTask,
  supportsTrainingObservationTask, taskObservationCollectorFor } from './task-training-observation-lifecycle.js';

const evidence: EvidenceReference = {
  path: 'synthetic-lifecycle/s1-observation.json',
  sha256: 'a'.repeat(64),
  boundary: 'actual_tool_http_x402_local_evm_application_store',
};
const txHash = `0x${'b'.repeat(64)}`;

test('training observation routing preserves legacy collectors and supports open paid and chain tasks', () => {
  const routes = new Map<string, string>([
    ['S1', 's1'], ['S2', 's2'], ['S4', 's4'], ['M1', 'm1_training'],
    ['H1', 'paid_data'], ['M3', 'chain'], ['M4', 'chain'], ['H2', 'chain'],
  ]);
  for (const [taskId, route] of routes) {
    assert.equal(taskObservationCollectorFor('training', taskId), route);
    assert.equal(supportsTrainingObservationTask(taskId), true);
    assert.equal(supportsObservationTask('training', taskId), true);
  }
  for (const taskId of ['S3', 'M2', 'H3', 'U1', 'unknown']) {
    assert.equal(taskObservationCollectorFor('training', taskId), null);
    assert.equal(supportsTrainingObservationTask(taskId), false);
  }
});

test('ranked observation routing selects only collectors with a complete task boundary', () => {
  const routes = new Map<string, string>([
    ['S1','s1'], ['S2','s2'], ['S4','s4'], ['S3', 's3'], ['M1', 'paid_data'], ['M2', 'paid_data'], ['H1', 'paid_data'],
    ['H3','composite'], ['U1','composite'],
    ['M3', 'chain'], ['M4', 'chain'], ['H2', 'chain'],
  ]);
  for (const [taskId, route] of routes) {
    assert.equal(taskObservationCollectorFor('ranked', taskId), route);
    assert.equal(supportsObservationTask('ranked', taskId), true);
  }
  for (const taskId of ['unknown']) {
    assert.equal(taskObservationCollectorFor('ranked', taskId), null);
    assert.equal(supportsObservationTask('ranked', taskId), false);
  }
});

function inputWithCoverage(transfersComplete: boolean, deliverPrincipal: boolean): EvaluateTaskInput {
  const binding: TaskEvidenceBinding = {
    ownerId: '00000000-0000-4000-8000-000000000001',
    agentId: '00000000-0000-4000-8000-000000000002',
    runId: '00000000-0000-4000-8000-000000000003',
    environmentId: 'synthetic-s1-env',
    releaseIdentity: 'synthetic-lifecycle-release',
    manifestHash: 'c'.repeat(64),
    caseId: 'synthetic-s1-case',
    caseHash: 'd'.repeat(64),
    rubricHash: 'e'.repeat(64),
    taskId: 'S1',
  };
  const recipient = '0x1111111111111111111111111111111111111111';
  const taskCase = {
    mode: 'training', taskId: 'S1', caseId: binding.caseId, caseHash: binding.caseHash,
    rubricHash: binding.rubricHash, executionIdentityHash: 'f'.repeat(64), taskDeadlineSeconds: 120,
    initialState: { stateSha256: '1'.repeat(64), balances: [
      { account: 'participant', assetId: 'USDC', amountUnits: '10' },
      { account: 'participant', assetId: 'ETH', amountUnits: '100' },
      { account: recipient, assetId: 'USDC', amountUnits: '0' },
    ], allowances: [] },
    objective: { tokenAssetId: 'USDC', sender: 'participant', recipient,
      exactPrincipalUnits: '10', nativeReserveWei: '1', unrelatedEffectBaselineSha256: '2'.repeat(64) },
  } as unknown as TaskCase;
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 1, captureEvidence: evidence,
    coverage: { transfers: transfersComplete ? 'complete' : 'incomplete', balances: 'complete' },
    transfers: deliverPrincipal ? [{ kind: 'transfer', observationId: 's1-principal', sequence: 1, actionSequence: 0,
      source: 'persisted_observer', binding, evidence, from: 'participant', to: recipient,
      assetId: 'USDC', amountUnits: '10', receiptStatus: 'success', transactionHash: txHash, operation: 'principal' }] : [],
    payments: [], stateMutations: [],
    finalStates: [{ kind: 'final_state', observationId: 's1-final', sequence: 1, actionSequence: 0,
      source: 'persisted_observer', binding, evidence,
      balances: [
        { account: 'participant', assetId: 'ETH', amountUnits: '100' },
        { account: recipient, assetId: 'USDC', amountUnits: deliverPrincipal ? '10' : '0' },
      ], allowances: [] }],
    allowanceChanges: [], allowanceUses: [], answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
  };
  return {
    taskCase,
    release: { manifestHash: binding.manifestHash, releaseIdentity: binding.releaseIdentity,
      executionIdentity: {} as EvaluateTaskInput['release']['executionIdentity'], costPolicy: {} as EvaluateTaskInput['release']['costPolicy'] },
    run: { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0,
      observationCutoffSequence: 1, cutoffStatus: 'authoritative', cutoffEvidence: evidence },
    observations,
  };
}

test('candidate gate leaves unknown evidence unsealed and seals only known rubric results', async () => {
  let sealCalls = 0;
  const unknown = await preflightAndSealKnownCandidate(inputWithCoverage(false, false), async () => { sealCalls += 1; return 'sealed'; });
  assert.equal(unknown.status, 'unknown');
  assert.equal(unknown.result.status, 'unknown');
  assert.equal(sealCalls, 0, 'an incomplete candidate never enters immutable storage');

  const passed = await preflightAndSealKnownCandidate(inputWithCoverage(true, true), async () => { sealCalls += 1; return 'sealed'; });
  assert.equal(passed.status, 'known');
  assert.equal(passed.result.status, 'known');
  assert.equal(passed.result.outcome, 'passed');
  assert.equal(passed.sealed, 'sealed');
  assert.equal(sealCalls, 1);

  const knownFailure = await preflightAndSealKnownCandidate(inputWithCoverage(true, false), async () => { sealCalls += 1; return 'sealed'; });
  assert.equal(knownFailure.status, 'known');
  assert.equal(knownFailure.result.status, 'known');
  assert.equal(knownFailure.result.outcome, 'failed');
  assert.equal(sealCalls, 2, 'a known rubric failure remains an immutable evaluation candidate');
});

test('synthetic isolated-PG resume reloads an evaluated bundle, proves the exact fence, and completes once',
  { skip: process.env.OID_TASK_TRAINING_LIFECYCLE_PG_TEST !== '1' }, async () => {
    const sourceUrlValue = process.env.OID_DATABASE_URL;
    assert.ok(sourceUrlValue, 'The Docker runtime must provide its local owner DB URL');
    const sourceUrl = new URL(sourceUrlValue);
    assert.equal(sourceUrl.hostname, 'postgres', 'This synthetic contract test must run inside the owner-identity Docker network');
    assert.equal(sourceUrl.username, 'oid_owner');
    assert.equal(sourceUrl.pathname, '/owner_identity');
    const databaseName = `oid_lifecycle_${randomUUID().replaceAll('-', '')}`;
    const testUrl = new URL(sourceUrlValue);
    testUrl.pathname = `/${databaseName}`;
    const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
    const client = postgres(testUrl.toString(), { max: 8, connect_timeout: 10 });
    const db = drizzle(client) as unknown as OwnerDatabase;
    let databaseCreated = false;
    try {
      await admin.unsafe(`CREATE DATABASE ${databaseName}`);
      databaseCreated = true;
      const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], {
        cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: testUrl.toString() }, encoding: 'utf8',
      });
      assert.equal(migration.status, 0, 'The isolated lifecycle contract database must migrate successfully');
      const fixture = await addFixture(client, { includeEvaluation: false, fence: false });
      assert.ok(fixture.evaluationInput, 'The shared fixture must contain the canonical sealed S1 input');
      const releaseSource = {
        async getActiveAdmissionRelease() { return null; },
        async getValidatedReleaseRecord(identity: string, manifestHash: string) {
          return identity === fixture.record.releaseIdentity && manifestHash === fixture.record.manifestHash
            ? fixture.record as never : null;
        },
      } satisfies TaskReleaseQuerySource;
      // Synthetic source for orchestration/DB ordering only; this test does not claim raw packet verification or BEF proof.
      const evidenceSource: TaskEvaluationEvidenceSource = {
        async load(input) {
          if (input.runId !== fixture.runId || input.taskIndex !== 0 || input.closureId !== fixture.closureId) return null;
          return structuredClone(fixture.evaluationInput) as EvaluateTaskInput;
        },
      };
      const target = { runId: fixture.runId, taskIndex: 0 };
      const recorded = await recordTaskEvaluation({ db, taskReleaseSource: releaseSource, evidenceSource,
        evaluatorSourceHash: await getTaskEvaluatorBuildHash() }, target);
      assert.equal(recorded.evaluation.result.status, 'known');
      assert.equal(recorded.evaluation.result.outcome, 'passed');

      const initialPreparation = await getTaskPreparation(db, fixture.preparationId);
      assert.ok(initialPreparation);
      let fenceCalls = 0;
      let fenceProofCalls = 0;
      let unexpectedObserverCalls = 0;
      const fenceReference: EvidenceReference = { path: `synthetic-lifecycle/${fixture.preparationId}-fence.json`,
        sha256: createHash('sha256').update(`${fixture.preparationId}:fence`).digest('hex'),
        boundary: 'actual_tool_http_x402_local_evm_application_store' };
      const preparationAdapter: TaskPreparationAdapter = {
        async prepare() { throw new Error('unexpected_prepare_call'); },
        async reconcile() { throw new Error('unexpected_reconcile_call'); },
        async fence(input) {
          fenceCalls += 1;
          assert.equal(input.intent.preparationId, fixture.preparationId);
          assert.equal(input.generationId, fixture.generationId);
          return { confirmed: true, preparationId: input.intent.preparationId, leaseId: input.intent.leaseId,
            environmentId: input.intent.environmentId, generationId: input.generationId, evidence: fenceReference };
        },
      };
      const observerPort: BefReadOnlyPostgresPort = {
        environmentId: fixture.environmentId,
        async withRepeatableRead<T>(_callback: (query: (statement: string, parameters?: readonly unknown[]) => Promise<unknown>) => Promise<T>) {
          unexpectedObserverCalls += 1;
          throw new Error('collector_should_not_run_for_a_retained_bundle');
        },
        async readFenceProof(input): Promise<BefFenceProof> {
          fenceProofCalls += 1;
          if (fenceCalls === 0 || input.preparationId !== initialPreparation.intent.preparationId ||
              input.generationId !== fixture.generationId) return { generation: null, preparation: null };
          const timestamp = new Date().toISOString();
          const intent = initialPreparation.intent;
          return {
            generation: { generation_id: fixture.generationId, env_id: fixture.environmentId, status: 'fenced', fenced_at: timestamp },
            preparation: { preparation_id: fixture.preparationId, status: 'fenced', fence_confirmed_at: timestamp,
              preparation_generation_id: fixture.generationId, public_pins_sha256: taskPreparationPublicPinsSha256(intent),
              manifest_sha256: intent.environmentManifestSha256, environment_manifest_hash: intent.environmentManifestSha256 },
          };
        },
      };
      let leaseAssertions = 0;
      const deps = { db, taskReleaseSource: releaseSource, repositoryRoot: '/workspace', evidenceSource,
        observerPorts: { postgresByEnvironment: { [fixture.environmentId]: observerPort }, rpcByEnvironment: {},
          evidenceSink: { async write() { unexpectedObserverCalls += 1; throw new Error('unexpected_capture_write'); } } },
        preparationAdapter, async assertLeaseHeld() { leaseAssertions += 1; } };
      const result = await processClosedTrainingTask(deps, target);
      assert.deepEqual({ status: result.status, stage: result.stage, taskId: 'taskId' in result ? result.taskId : null,
        outcome: 'outcome' in result ? result.outcome : null, replayed: 'replayed' in result ? result.replayed : null },
      { status: 'run_completed', stage: 'terminalize', taskId: 'S1', outcome: 'passed', replayed: false });
      assert.equal(fenceCalls, 1, 'only the exact original preparation generation is fenced');
      assert.equal(fenceProofCalls, 1, 'the separate observer confirms the persisted original fence');
      assert.equal(unexpectedObserverCalls, 0, 'retained sealed evidence resumes without re-collection or packet writes');
      assert.ok(leaseAssertions >= 6, 'the worker lease is checked between lifecycle stages');

      const persisted = await client`SELECT r.status,r.finished_at,t.status AS task_status,c.status AS claim_status,
          (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slot_count,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.evaluated') AS evaluated_events,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='run.completed') AS completed_events,
          (SELECT count(*)::int FROM oid_run_task_evaluation WHERE run_id=r.id) AS evaluation_count,
          (SELECT state FROM oid_run_reservation WHERE run_id=r.id) AS reservation_state,
          (SELECT state FROM oid_run_budget_hold WHERE run_id=r.id) AS hold_state,
          l.state AS lease_state
        FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=0
        JOIN oid_run_dispatch_claim c ON c.run_id=r.id
        JOIN oid_task_environment_lease l ON l.preparation_id=${fixture.preparationId}
        WHERE r.id=${fixture.runId}`;
      assert.equal(persisted[0]?.status, 'completed');
      assert.ok(persisted[0]?.finished_at);
      assert.equal(persisted[0]?.task_status, 'completed');
      assert.equal(persisted[0]?.claim_status, 'released');
      assert.equal(persisted[0]?.slot_count, 0);
      assert.equal(persisted[0]?.evaluated_events, 1);
      assert.equal(persisted[0]?.completed_events, 1);
      assert.equal(persisted[0]?.evaluation_count, 1);
      assert.equal(persisted[0]?.reservation_state, 'debited');
      assert.equal(persisted[0]?.hold_state, 'charged');
      assert.equal(persisted[0]?.lease_state, 'fenced');

      const replay = await processClosedTrainingTask(deps, target);
      assert.deepEqual({ status: replay.status, replayed: 'replayed' in replay ? replay.replayed : null },
        { status: 'run_completed', replayed: true });
      assert.equal(fenceCalls, 1, 'a sealed fence is replayed from the stored owner proof');
      assert.equal(unexpectedObserverCalls, 0);
      assert.equal((await client`SELECT count(*)::int AS count FROM oid_run_event WHERE run_id=${fixture.runId} AND event_type='run.completed'`)[0]?.count, 1);

      async function assertRejectedBeforeResume(options: { ranked?: boolean; cancellationHistory?: boolean }, reasonCode: string) {
        const rejectedFixture = await addFixture(client, { fence: false,
          ...(options.cancellationHistory ? { cancellationHistory: true } : {}) });
        if (options.ranked) await client`UPDATE oid_benchmark_run SET mode='ranked' WHERE id=${rejectedFixture.runId}`;
        const calls = { evidence: 0, release: 0, collection: 0, sink: 0, fence: 0, fenceProof: 0 };
        const rejectingEvidenceSource: TaskEvaluationEvidenceSource = {
          async load() { calls.evidence += 1; return structuredClone(rejectedFixture.evaluationInput) as EvaluateTaskInput; },
        };
        const rejectingReleaseSource: TaskReleaseQuerySource = {
          async getActiveAdmissionRelease() { return null; },
          async getValidatedReleaseRecord(identity: string, manifestHash: string) {
            calls.release += 1;
            return identity === rejectedFixture.record.releaseIdentity && manifestHash === rejectedFixture.record.manifestHash
              ? rejectedFixture.record as never : null;
          },
        };
        const rejectingAdapter: TaskPreparationAdapter = {
          async prepare() { throw new Error('unexpected_prepare_call'); },
          async reconcile() { throw new Error('unexpected_reconcile_call'); },
          async fence() { calls.fence += 1; throw new Error('unexpected_fence_call'); },
        };
        const rejectingObserver: BefReadOnlyPostgresPort = {
          environmentId: rejectedFixture.environmentId,
          async withRepeatableRead<T>(_callback: (query: (statement: string, parameters?: readonly unknown[]) => Promise<unknown>) => Promise<T>) {
            calls.collection += 1;
            throw new Error('unexpected_collection_call');
          },
          async readFenceProof(): Promise<BefFenceProof> {
            calls.fenceProof += 1;
            return { generation: null, preparation: null };
          },
        };
        const rejected = await processClosedTrainingTask({ db, taskReleaseSource: rejectingReleaseSource,
          repositoryRoot: '/workspace', evidenceSource: rejectingEvidenceSource,
          observerPorts: { postgresByEnvironment: { [rejectedFixture.environmentId]: rejectingObserver }, rpcByEnvironment: {},
            evidenceSink: { async write() { calls.sink += 1; throw new Error('unexpected_evidence_write'); } } },
          preparationAdapter: rejectingAdapter, async assertLeaseHeld() {} },
        { runId: rejectedFixture.runId, taskIndex: 0 });
        assert.deepEqual({ status: rejected.status, stage: 'stage' in rejected ? rejected.stage : null,
          reasonCode: 'reasonCode' in rejected ? rejected.reasonCode : null },
        { status: 'blocked', stage: 'target', reasonCode });
        assert.deepEqual(calls, { evidence: 0, release: 0, collection: 0, sink: 0, fence: 0, fenceProof: 0 });
        const unchanged = await client`SELECT r.status,t.status AS task_status,l.state AS lease_state,
            (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type IN ('task.terminalized','run.completed')) AS terminal_events
          FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=0
          JOIN oid_task_environment_lease l ON l.preparation_id=${rejectedFixture.preparationId} WHERE r.id=${rejectedFixture.runId}`;
        assert.deepEqual(unchanged.map((row) => ({ status: row.status, taskStatus: row.task_status,
          leaseState: row.lease_state, terminalEvents: row.terminal_events })),
        [{ status: 'running', taskStatus: 'active', leaseState: 'leased', terminalEvents: 0 }]);
      }

      await assertRejectedBeforeResume({ ranked: true }, 'ranked_full_task_set_required');
      await assertRejectedBeforeResume({ cancellationHistory: true }, 'run_cancellation_history');
    } finally {
      try {
        await client.end();
      } finally {
        try {
          if (databaseCreated) await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
        } finally {
          await admin.end();
        }
      }
    }
  });
