import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import type { EvaluateTaskInput } from './task-evaluator.js';
import { type TaskReleaseQuerySource } from './task-release.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { completeKnownTrainingRun, finalizeKnownTrainingTask } from './task-run-completion.js';

const enabled = process.env.OID_TASK_RUN_COMPLETION_PG_TEST === '1';

test('private known training completion is atomic, replayable, and waits for exact original fences', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The Docker runtime must provide its local owner DB URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'This contract test must run inside the owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
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
    assert.equal(migration.status, 0, 'The isolated task-completion acceptance database must migrate successfully');

    const source = { async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord(identity: string, manifest: string) {
        return fixtures.find((fixture) => fixture.record.releaseIdentity === identity && fixture.record.manifestHash === manifest)?.record as never ?? null;
      } } satisfies TaskReleaseQuerySource;
    const fixtures = [
      await addFixture(client, { overallDeadlinePast: true }),
      await addFixture(client, { includeEvaluation: false }),
      await addFixture(client, { known: false }),
      await addFixture(client, { fence: false }),
      await addFixture(client, { openCutoff: true }),
      await addFixture(client, { cancellationHistory: true }),
      await addFixture(client, { failedOutcome: true }),
      await addFixture(client, { multiTask: true }),
      await addFixture(client, { multiTask: true, failedOutcome: true }),
      await addFixture(client, { multiTask: true, known: false }),
      await addFixture(client, { multiTask: true, fence: false }),
      await addFixture(client, { multiTask: true, cancellationHistory: true }),
      await addFixture(client, { unterminalPredecessor: true }),
    ];
    const deps = { db, taskReleaseSource: source, evidenceSource: { async load(input: { runId: string; taskIndex: number; closureId: string }) {
      return structuredClone(fixtures.find((fixture) => fixture.runId === input.runId)?.evaluationInput ?? null) as EvaluateTaskInput | null;
    } } };

    const successorSnapshot = async (runId: string, ownerId: string) => {
      const result = await client`SELECT r.status,r.started_at,r.overall_deadline,r.finished_at,c.claim_id,c.status AS claim_status,
          (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slot_count,
          (SELECT state FROM oid_run_reservation WHERE run_id=r.id) AS reservation_state,
          (SELECT amount_units::text FROM oid_run_reservation WHERE run_id=r.id) AS reservation_amount,
          (SELECT state FROM oid_run_budget_hold WHERE run_id=r.id) AS budget_state,
          (SELECT amount_units::text FROM oid_run_budget_hold WHERE run_id=r.id) AS budget_amount,
          (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=${ownerId}) AS ledger_count,
          (SELECT COALESCE(sum(amount_units),0)::text FROM oid_ledger_entry WHERE owner_id=${ownerId}) AS ledger_sum
        FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id WHERE r.id=${runId}`;
      return result[0];
    };

    const successorBefore = await successorSnapshot(fixtures[7]!.runId, fixtures[7]!.ownerId);
    const finalized = await finalizeKnownTrainingTask(deps, { runId: fixtures[7]!.runId, taskIndex: 0 });
    assert.deepEqual({ status: finalized.status, replayed: finalized.replayed }, { status: 'completed', replayed: false });
    const successorAfter = await successorSnapshot(fixtures[7]!.runId, fixtures[7]!.ownerId);
    assert.deepEqual(successorAfter, successorBefore,
      'non-final task terminalization leaves the run clock, single charge, claim and execution slot unchanged');
    const successorState = await client`SELECT t.status,t.finished_at,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=t.run_id AND event_type='task.terminalized') AS terminal_events,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=t.run_id AND event_type='run.completed') AS run_completed_events,
        (SELECT status FROM oid_run_task WHERE run_id=t.run_id AND task_index=1) AS next_task_status
      FROM oid_run_task t WHERE t.run_id=${fixtures[7]!.runId} AND t.task_index=0`;
    assert.equal(successorState[0]?.status, 'completed');
    assert.ok(successorState[0]?.finished_at);
    assert.equal(successorState[0]?.terminal_events, 1);
    assert.equal(successorState[0]?.run_completed_events, 0);
    assert.equal(successorState[0]?.next_task_status, 'queued');
    const finalizedReplay = await finalizeKnownTrainingTask(deps, { runId: fixtures[7]!.runId, taskIndex: 0 });
    assert.equal(finalizedReplay.replayed, true);
    assert.equal(finalizedReplay.finishedAt, finalized.finishedAt);
    await assert.rejects(finalizeKnownTrainingTask(deps, { runId: fixtures[7]!.runId, taskIndex: 1 }),
      (error: { code?: string }) => error.code === 'FINAL_TASK_REQUIRES_RUN_COMPLETION');
    const replayEventCount = await client`SELECT count(*)::int AS count FROM oid_run_event
      WHERE run_id=${fixtures[7]!.runId} AND event_type='task.terminalized'`;
    assert.equal(replayEventCount[0]?.count, 1);

    const knownFailed = await finalizeKnownTrainingTask(deps, { runId: fixtures[8]!.runId, taskIndex: 0 });
    assert.equal(knownFailed.status, 'failed', 'a known failed task is terminal but does not end the selected training run');
    assert.equal((await finalizeKnownTrainingTask(deps, { runId: fixtures[8]!.runId, taskIndex: 0 })).replayed, true);
    await assert.rejects(finalizeKnownTrainingTask(deps, { runId: fixtures[9]!.runId, taskIndex: 0 }),
      (error: { code?: string }) => error.code === 'TASK_EVALUATION_NOT_KNOWN');
    await assert.rejects(finalizeKnownTrainingTask(deps, { runId: fixtures[10]!.runId, taskIndex: 0 }),
      (error: { code?: string }) => error.code === 'TASK_ORIGINAL_GENERATION_NOT_FENCED');
    await assert.rejects(finalizeKnownTrainingTask(deps, { runId: fixtures[11]!.runId, taskIndex: 0 }),
      (error: { code?: string }) => error.code === 'RUN_CANCELLATION_HISTORY');
    await assert.rejects(finalizeKnownTrainingTask(deps, { runId: fixtures[12]!.runId, taskIndex: 1 }),
      (error: { code?: string }) => error.code === 'RUN_TASK_PREDECESSOR_NOT_TERMINAL');
    for (const fixture of fixtures.slice(9)) {
      const untouched = await client`SELECT r.status,t.status AS task_status,
          (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slot_count,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='task.terminalized') AS terminal_events
        FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id AND t.task_index=0 WHERE r.id=${fixture.runId}`;
      assert.equal(untouched[0]?.status, 'running');
      assert.equal(untouched[0]?.task_status, 'active');
      assert.equal(untouched[0]?.slot_count, 1);
      assert.equal(untouched[0]?.terminal_events, 0);
    }

    const complete = await completeKnownTrainingRun(deps, { runId: fixtures[0]!.runId });
    assert.equal(complete.status, 'completed');
    assert.equal(complete.replayed, false);
    assert.ok(new Date(complete.finishedAt).getTime() > new Date(fixtures[0]!.overallDeadline).getTime(),
      'late evidence reconciliation may complete a run whose admitted cutoffs were already resolved');
    const replay = await completeKnownTrainingRun(deps, { runId: fixtures[0]!.runId });
    assert.equal(replay.replayed, true);
    assert.equal(replay.finishedAt, complete.finishedAt);
    const finalRows = await client`SELECT r.status,r.started_at,r.overall_deadline,r.finished_at,t.status AS task_status,
        c.status AS claim_status,c.released_at,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='run.completed') AS completion_events,
        (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slots,
        (SELECT state FROM oid_run_reservation WHERE run_id=r.id) AS reservation_state,
        (SELECT state FROM oid_run_budget_hold WHERE run_id=r.id) AS budget_state
      FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
      JOIN oid_run_dispatch_claim c ON c.run_id=r.id WHERE r.id=${fixtures[0]!.runId}`;
    assert.equal(finalRows[0]?.status, 'completed');
    assert.equal(finalRows[0]?.task_status, 'completed');
    assert.equal(finalRows[0]?.claim_status, 'released');
    assert.equal(finalRows[0]?.completion_events, 1);
    assert.equal(finalRows[0]?.slots, 0);
    assert.equal(finalRows[0]?.reservation_state, 'debited');
    assert.equal(finalRows[0]?.budget_state, 'charged');

    await client`UPDATE oid_agent_policy SET training=false,revision=revision+1 WHERE agent_id=${fixtures[0]!.agentId}`;
    const replayAfterLaterRevocation = await completeKnownTrainingRun(deps, { runId: fixtures[0]!.runId });
    assert.equal(replayAfterLaterRevocation.replayed, true,
      'later permission removal must not invalidate the immutable completion replay');
    assert.equal(replayAfterLaterRevocation.finishedAt, complete.finishedAt);

    const failed = await completeKnownTrainingRun(deps, { runId: fixtures[6]!.runId });
    assert.equal(failed.status, 'completed', 'a known failed task is terminal but does not stop run completion');
    const failedTask = await client`SELECT status FROM oid_run_task WHERE run_id=${fixtures[6]!.runId} AND task_index=0`;
    assert.equal(failedTask[0]?.status, 'failed');

    await assert.rejects(completeKnownTrainingRun(deps, { runId: fixtures[1]!.runId }),
      (error: { code?: string }) => error.code === 'RUN_EVALUATIONS_INCOMPLETE');
    await assert.rejects(completeKnownTrainingRun(deps, { runId: fixtures[2]!.runId }),
      (error: { code?: string }) => error.code === 'TASK_EVALUATION_NOT_KNOWN');
    await assert.rejects(completeKnownTrainingRun(deps, { runId: fixtures[3]!.runId }),
      (error: { code?: string }) => error.code === 'TASK_ORIGINAL_GENERATION_NOT_FENCED');
    await assert.rejects(completeKnownTrainingRun(deps, { runId: fixtures[4]!.runId }),
      (error: { code?: string }) => error.code === 'TASK_CUTOFF_NOT_FINAL');
    await assert.rejects(completeKnownTrainingRun(deps, { runId: fixtures[5]!.runId }),
      (error: { code?: string }) => error.code === 'RUN_CANCELLATION_HISTORY');
    const rejectedRows = await client`SELECT status,finished_at FROM oid_benchmark_run
      WHERE id IN (${fixtures[1]!.runId},${fixtures[2]!.runId},${fixtures[3]!.runId},${fixtures[4]!.runId},${fixtures[5]!.runId})`;
    assert.equal(rejectedRows.length, 5);
    assert.ok(rejectedRows.every((row) => row.status === 'running' && row.finished_at === null),
      'Rejected completions must not terminalize runs');
    const unresolvedSlotCount = await client`SELECT count(*)::int AS count FROM oid_run_execution_slot
      WHERE run_id IN (${fixtures[1]!.runId},${fixtures[2]!.runId},${fixtures[3]!.runId},${fixtures[4]!.runId},${fixtures[5]!.runId})`;
    assert.equal(unresolvedSlotCount[0]?.count, 5, 'Failed verification retains each run slot');
    return;
  } finally {
    await client.end();
    await admin.end();
  }
});

