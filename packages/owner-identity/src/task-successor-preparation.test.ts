import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { EvaluateTaskInput } from './task-evaluator.js';
import { finalizeKnownTrainingTask } from './task-run-completion.js';
import { addFixture, evidence } from './task-run-completion.test-fixture.js';
import {
  assertSuccessorTaskPreparationReady,
  assertTaskPreparationReady,
  beginSuccessorTaskPreparation,
  beginTaskPreparation,
  createPreparedSuccessorTaskStartPort,
  createPreparedTaskStartPort,
  prepareSuccessorTaskExecution,
  prepareTaskExecution,
  type TaskPreparationAdapter,
  type TaskPreparationDependencies,
  type TaskPreparationTarget,
} from './task-preparation.js';
import type { TaskEvaluationEvidenceSource } from './task-result-service.js';
import type { TaskReleaseQuerySource } from './task-release.js';

const enabled = process.env.OID_TASK_SUCCESSOR_PREPARATION_PG_TEST === '1';
const policyVersion = 'local-bef-successor-preparation/v1';
const rawEvidence = (label: string) => ({
  ...evidence(label),
  boundary: 'actual_tool_http_x402_local_evm_application_store' as const,
});

test('successor preparation is ordered, replay-bound, deadline-bounded, and does not restart or recharge the run', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The Docker runtime must provide its local owner DB URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'This contract test must run inside the owner-identity Docker network');
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
    assert.equal(migration.status, 0, 'The isolated successor-preparation database must migrate successfully');

    const fixtures: Awaited<ReturnType<typeof addFixture>>[] = [];
    const releaseSource = {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord(identity: string, manifest: string) {
        const fixture = fixtures.find((candidate) => candidate.record.releaseIdentity === identity && candidate.record.manifestHash === manifest);
        return fixture?.record as never ?? null;
      },
    } satisfies TaskReleaseQuerySource;
    const evidenceSource: TaskEvaluationEvidenceSource = {
      async load(input) {
        const fixture = fixtures.find((candidate) => candidate.runId === input.runId);
        if (!fixture || input.taskIndex !== 0 || input.closureId !== fixture.closureId || !fixture.evaluationInput) return null;
        return structuredClone(fixture.evaluationInput) as EvaluateTaskInput;
      },
    };
    const completionDeps = { db, taskReleaseSource: releaseSource, evidenceSource };

    function dependenciesFor(targetEnvironment?: string): TaskPreparationDependencies & { predecessorEvidenceSource: TaskEvaluationEvidenceSource } {
      const adapter: TaskPreparationAdapter = {
        prepare: async ({ intent }) => ({ status: 'prepared', result: {
          environmentId: intent.environmentId,
          generationId: randomUUID(),
          manifestHash: intent.manifestHash,
          applicationSourceHash: intent.applicationSourceHash,
          environmentManifestSha256: intent.environmentManifestSha256,
          initialStateSha256: intent.initialStateSha256,
          fixtureEvidence: rawEvidence(`${intent.preparationId}-fixture`),
          baselineEvidence: rawEvidence(`${intent.preparationId}-baseline`),
        } }),
        reconcile: async ({ intent }) => ({ status: 'unknown', generationId: intent.preparationId, reasonCode: 'adapter_outcome_unknown' }),
        fence: async ({ intent, generationId }) => ({ confirmed: true, preparationId: intent.preparationId,
          leaseId: intent.leaseId, environmentId: intent.environmentId, generationId,
          evidence: rawEvidence(`${intent.preparationId}-fence`) }),
        hasUsableStartSession: () => true,
      };
      return {
        db,
        releaseSource,
        preparationAdapter: adapter,
        environmentSelector: { async selectEnvironment({ runId }) { return targetEnvironment ?? `successor-${runId.slice(0, 12)}`; } },
        predecessorEvidenceSource: evidenceSource,
      };
    }

    async function configuredFixture(options: Parameters<typeof addFixture>[1] = {}) {
      const fixture = await addFixture(client, { multiTask: true, successorPreparationPolicyVersion: policyVersion,
        successorPreparationTimeoutSeconds: 180, ...options });
      fixtures.push(fixture);
      return fixture;
    }
    async function finalizePredecessor(fixture: Awaited<ReturnType<typeof addFixture>>) {
      return finalizeKnownTrainingTask(completionDeps, { runId: fixture.runId, taskIndex: 0 });
    }
    async function hasSuccessorPreparation(runId: string) {
      const rows = await client`SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=${runId} AND task_index=1`;
      return rows.length === 1;
    }
    async function wait(milliseconds: number) { await new Promise((resolve) => setTimeout(resolve, milliseconds)); }

    const positive = await configuredFixture();
    const target: TaskPreparationTarget = { runId: positive.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${positive.runId}`)[0]!.claim_id };
    const firstTaskApi = dependenciesFor(positive.environmentId);
    await assert.rejects(beginTaskPreparation(firstTaskApi, target), (error: { code?: string }) => error.code === 'FIRST_TASK_PREPARATION_REQUIRED');
    await assert.rejects(prepareTaskExecution(firstTaskApi, target), (error: { code?: string }) => error.code === 'FIRST_TASK_PREPARATION_REQUIRED');
    await assert.rejects(assertTaskPreparationReady(db, target), (error: { code?: string }) => error.code === 'FIRST_TASK_PREPARATION_REQUIRED');
    await assert.rejects(createPreparedTaskStartPort(firstTaskApi, async () => {}).readCandidatePreparationId(target),
      (error: { code?: string }) => error.code === 'FIRST_TASK_PREPARATION_REQUIRED');

    const finalized = await finalizePredecessor(positive);
    assert.deepEqual({ status: finalized.status, replayed: finalized.replayed }, { status: 'completed', replayed: false });
    const before = await client`SELECT r.status,r.started_at,r.overall_deadline,r.finished_at,r.environment_id,c.claim_id,c.status AS claim_status,
        s.state AS slot_state,(SELECT state FROM oid_run_reservation WHERE run_id=r.id) AS reservation_state,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reservation_units,
        (SELECT state FROM oid_run_budget_hold WHERE run_id=r.id) AS hold_state,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS hold_units
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${positive.runId}`;

    const deps = dependenciesFor(positive.environmentId);
    const [beginA, beginB] = await Promise.all([
      beginSuccessorTaskPreparation(deps, target), beginSuccessorTaskPreparation(deps, target),
    ]);
    assert.equal(beginA.preparation.intent.preparationId, beginB.preparation.intent.preparationId,
      'concurrent preparation requests reuse the same immutable task identity');
    assert.deepEqual([beginA.replayed, beginB.replayed].sort(), [false, true]);

    const ready = await prepareSuccessorTaskExecution(deps, target);
    assert.equal(ready.intent.taskIndex, 1);
    assert.equal(ready.observation.status, 'ready');
    const readyReplay = await assertSuccessorTaskPreparationReady(deps, target);
    assert.equal(readyReplay.intent.preparationId, ready.intent.preparationId);
    assert.equal(readyReplay.observation.status, 'ready');

    const bypassPort = createPreparedSuccessorTaskStartPort(deps, async () => {});
    const minimumValidUntil = new Date(Date.now() + 60_000).toISOString();
    await assert.rejects(db.transaction((tx) => bypassPort.assertReadyInTransaction(tx, target, ready.intent.preparationId, minimumValidUntil)),
      (error: { code?: string }) => error.code === 'TASK_PREPARATION_NOT_READY');

    const successorPort = createPreparedSuccessorTaskStartPort(deps, async () => {});
    const candidateId = await successorPort.readCandidatePreparationId(target);
    assert.equal(candidateId, ready.intent.preparationId);
    const checked = await db.transaction((tx) => successorPort.assertReadyInTransaction(tx, target, candidateId!, minimumValidUntil));
    assert.equal(checked.intent.taskIndex, 1);
    assert.equal(successorPort.hasUsableStartSession(checked, minimumValidUntil), true);
    await assert.rejects(db.transaction((tx) => successorPort.assertReadyInTransaction(tx, target, randomUUID(), minimumValidUntil)),
      (error: { code?: string }) => error.code === 'TASK_PREPARATION_NOT_READY');

    const after = await client`SELECT r.status,r.started_at,r.overall_deadline,r.finished_at,r.environment_id,c.claim_id,c.status AS claim_status,
        s.state AS slot_state,(SELECT state FROM oid_run_reservation WHERE run_id=r.id) AS reservation_state,
        (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reservation_units,
        (SELECT state FROM oid_run_budget_hold WHERE run_id=r.id) AS hold_state,
        (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS hold_units
      FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${positive.runId}`;
    assert.deepEqual(after, before, 'successor preparation preserves the run clock, environment pointer, claim, slot, and original charge');

    const knownFailure = await configuredFixture({ failedOutcome: true });
    const failedPredecessor = await finalizePredecessor(knownFailure);
    assert.equal(failedPredecessor.status, 'failed');
    const failedDeps = dependenciesFor(knownFailure.environmentId);
    const failedTarget = { runId: knownFailure.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${knownFailure.runId}`)[0]!.claim_id };
    const failedSuccessor = await beginSuccessorTaskPreparation(failedDeps, failedTarget);
    assert.equal(failedSuccessor.preparation.intent.taskIndex, 1, 'a known ordinary failure may advance');

    const malformedViolation = await configuredFixture({ verifiedNativeReserveViolation: true,
      contradictoryMandatoryViolationResult: 'partial' });
    await finalizePredecessor(malformedViolation);
    const malformedTarget = { runId: malformedViolation.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${malformedViolation.runId}`)[0]!.claim_id };
    await assert.rejects(beginSuccessorTaskPreparation(dependenciesFor(malformedViolation.environmentId), malformedTarget),
      (error: { code?: string }) => error.code === 'RUN_TASK_PREDECESSOR_NOT_KNOWN');
    assert.equal(await hasSuccessorPreparation(malformedViolation.runId), false,
      'a partial result carrying a mandatory violation cannot create a successor preparation');

    const notTerminal = await configuredFixture();
    const notTerminalDeps = dependenciesFor(notTerminal.environmentId);
    const notTerminalTarget = { runId: notTerminal.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${notTerminal.runId}`)[0]!.claim_id };
    await assert.rejects(beginSuccessorTaskPreparation(notTerminalDeps, notTerminalTarget),
      (error: { code?: string }) => error.code === 'RUN_TASK_PREDECESSOR_NOT_TERMINAL');
    assert.equal(await hasSuccessorPreparation(notTerminal.runId), false, 'an active predecessor is not terminalized implicitly');

    const missingPolicy = await configuredFixture({ successorPreparationPolicyVersion: null, successorPreparationTimeoutSeconds: null });
    await finalizePredecessor(missingPolicy);
    await assert.rejects(beginSuccessorTaskPreparation(dependenciesFor(missingPolicy.environmentId), {
      runId: missingPolicy.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${missingPolicy.runId}`)[0]!.claim_id,
    }), (error: { code?: string }) => error.code === 'SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE');
    assert.equal(await hasSuccessorPreparation(missingPolicy.runId), false);

    const expiredPolicy = await configuredFixture({ successorPreparationTimeoutSeconds: 1 });
    await finalizePredecessor(expiredPolicy);
    await wait(1_100);
    await assert.rejects(beginSuccessorTaskPreparation(dependenciesFor(expiredPolicy.environmentId), {
      runId: expiredPolicy.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${expiredPolicy.runId}`)[0]!.claim_id,
    }), (error: { code?: string }) => error.code === 'SUCCESSOR_PREPARATION_WINDOW_EXPIRED');
    assert.equal(await hasSuccessorPreparation(expiredPolicy.runId), false);

    const crossedDeadline = await configuredFixture({ overallDeadlineSecondsFromNow: 3 });
    await finalizePredecessor(crossedDeadline);
    await wait(3_100);
    const crossedDeadlineTarget = { runId: crossedDeadline.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${crossedDeadline.runId}`)[0]!.claim_id };
    const afterOldDeadline = await beginSuccessorTaskPreparation(dependenciesFor(crossedDeadline.environmentId), crossedDeadlineTarget);
    assert.equal(afterOldDeadline.preparation.intent.taskIndex, 1,
      'preparation may cross the old overall deadline when the predecessor finished before it and the pinned preparation window remains open');

    const accessRevoked = await configuredFixture();
    await finalizePredecessor(accessRevoked);
    await client`UPDATE oid_agent SET access_revoked_at=clock_timestamp() WHERE id=${accessRevoked.agentId}`;
    await assert.rejects(beginSuccessorTaskPreparation(dependenciesFor(accessRevoked.environmentId), {
      runId: accessRevoked.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${accessRevoked.runId}`)[0]!.claim_id,
    }), (error: { code?: string }) => error.code === 'RUN_ACCESS_NOT_CURRENT');
    assert.equal(await hasSuccessorPreparation(accessRevoked.runId), false, 'revoked access cannot start successor preparation');

    const conflictingLease = await configuredFixture({ fence: false });
    const blockedReuse = await configuredFixture();
    await finalizePredecessor(blockedReuse);
    await assert.rejects(beginSuccessorTaskPreparation(dependenciesFor(conflictingLease.environmentId), {
      runId: blockedReuse.runId, taskIndex: 1,
      claimId: (await client`SELECT claim_id FROM oid_run_dispatch_claim WHERE run_id=${blockedReuse.runId}`)[0]!.claim_id,
    }), (error: { code?: string }) => error.code === 'TASK_ENVIRONMENT_BUSY');
    assert.equal(await hasSuccessorPreparation(blockedReuse.runId), false, 'a different run retains its original active environment lease');
  } finally {
    await client.end();
    await admin.end();
  }
});
