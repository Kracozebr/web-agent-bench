import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { requestRunCancellation, consumeRunCancellationOutbox } from './run-service.js';
import { finalizeKnownTrainingTask } from './task-run-completion.js';
import { beginSuccessorTaskPreparation, createTaskPreparationCancellationExecutor } from './task-preparation.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import type { EvaluateTaskInput } from './task-evaluator.js';

const enabled = process.env.OID_RUN_CANCELLATION_BETWEEN_TASKS_PG_TEST === '1';

test('post-start cancellation between known fenced tasks reuses the exact stored predecessor fence', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The Docker runtime must provide its isolated owner database URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'This contract test must run inside the owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const databaseName = `oid_cancel_gap_${randomUUID().replaceAll('-', '')}`;
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
    assert.equal(migration.status, 0, 'The isolated cancellation contract database must migrate successfully');

    const good = await addFixture(client, { multiTask: true, overallDeadlineSecondsFromNow: 3600 });
    const releaseSource = {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord(identity: string, manifestHash: string) {
        return identity === good.record.releaseIdentity && manifestHash === good.record.manifestHash ? good.record as never : null;
      },
    } satisfies TaskReleaseQuerySource;
    const completionDeps = {
      db, taskReleaseSource: releaseSource,
      evidenceSource: { async load(input: { runId: string; taskIndex: number; closureId: string }) {
        return input.runId === good.runId && input.taskIndex === 0 && input.closureId === good.closureId
          ? structuredClone(good.evaluationInput) as EvaluateTaskInput : null;
      } },
    };
    const finalized = await finalizeKnownTrainingTask(completionDeps, { runId: good.runId, taskIndex: 0 });
    assert.equal(finalized.status, 'completed');

    const before = await client`SELECT r.status,r.started_at,r.overall_deadline,
        rr.state AS reservation_state,rr.amount_units::text AS reservation_amount,
        h.state AS budget_state,h.amount_units::text AS budget_amount,
        c.status AS claim_status,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=r.owner_id AND entry_type='refund') AS refund_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold h ON h.run_id=r.id JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${good.runId}`;
    assert.equal(before[0]?.status, 'running');
    assert.equal(before[0]?.reservation_state, 'debited');
    assert.equal(before[0]?.budget_state, 'charged');
    assert.equal(before[0]?.claim_status, 'claimed');
    assert.equal(before[0]?.slot_state, 'running');

    const requested = await requestRunCancellation(db, {
      ownerId: good.ownerId, runId: good.runId, operationId: `cancelgap_${randomUUID().replaceAll('-', '')}`,
      reason: 'owner_voluntary',
    });
    assert.equal(requested.run.status, 'cancellation_requested');
    const pending = await client`SELECT payload_json FROM oid_run_outbox
      WHERE run_id=${good.runId} AND event_type='run.cancel.requested'`;
    assert.equal(pending.length, 1);
    assert.deepEqual(pending[0]?.payload_json.taskPreparation, {
      taskIndex: 0, preparationId: good.preparationId, generationId: good.generationId,
    }, 'the post-start gap pins the most recent preparation by its immutable index and original generation');

    let adapterFenceCalls = 0;
    let credentialClearCalls = 0;
    const unboundSessions: Array<{ runId: string; taskIndex: number }> = [];
    const fencer = createTaskPreparationCancellationExecutor({ db, releaseSource,
      environmentSelector: { async selectEnvironment() { throw new Error('cancellation does not select a new environment'); } },
      preparationAdapter: {
        async prepare() { throw new Error('no preparation is started by cancellation'); },
        async reconcile() { throw new Error('no reconciliation is needed for a stored fence'); },
        async fence() { adapterFenceCalls += 1; throw new Error('a stored fence must be replayed without a new adapter call'); },
        clearCredentials() { credentialClearCalls += 1; },
      },
    }, { unbindSession(runId, taskIndex) { unboundSessions.push({ runId, taskIndex }); } });
    await consumeRunCancellationOutbox(db, fencer, 100);

    const after = await client`SELECT r.status,r.started_at,r.overall_deadline,r.cancellation_evidence_hash,
        rr.state AS reservation_state,rr.amount_units::text AS reservation_amount,
        h.state AS budget_state,h.amount_units::text AS budget_amount,
        c.status AS claim_status,s.state AS slot_state,
        (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slot_count,
        (SELECT count(*)::int FROM oid_run_event WHERE run_id=r.id AND event_type='run.cancelled.after_start') AS terminal_events,
        (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=r.owner_id AND entry_type='refund') AS refund_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold h ON h.run_id=r.id JOIN oid_run_dispatch_claim c ON c.run_id=r.id
      LEFT JOIN oid_run_execution_slot s ON s.run_id=r.id WHERE r.id=${good.runId}`;
    assert.equal(after[0]?.status, 'cancelled');
    assert.ok(after[0]?.cancellation_evidence_hash);
    assert.equal(new Date(String(after[0]?.started_at)).toISOString(), new Date(String(before[0]?.started_at)).toISOString());
    assert.equal(new Date(String(after[0]?.overall_deadline)).toISOString(), new Date(String(before[0]?.overall_deadline)).toISOString());
    assert.equal(after[0]?.reservation_state, 'debited');
    assert.equal(after[0]?.reservation_amount, before[0]?.reservation_amount);
    assert.equal(after[0]?.budget_state, 'charged');
    assert.equal(after[0]?.budget_amount, before[0]?.budget_amount);
    assert.equal(after[0]?.claim_status, 'released');
    assert.equal(after[0]?.slot_count, 0);
    assert.equal(after[0]?.terminal_events, 1);
    assert.equal(after[0]?.refund_count, before[0]?.refund_count);
    assert.equal(adapterFenceCalls, 0, 'a confirmed original fence is consumed from immutable stored proof');
    assert.equal(credentialClearCalls, 1);
    assert.deepEqual(unboundSessions, [{ runId: good.runId, taskIndex: 0 }],
      'session cleanup uses the exact predecessor index returned by the stored preparation');

    const successorCase = good.record.manifest.cases.training.find((entry: { taskId: string }) => entry.taskId === 'S2');
    assert.ok(successorCase);
    await assert.rejects(beginSuccessorTaskPreparation({ db, releaseSource,
      predecessorEvidenceSource: completionDeps.evidenceSource,
      environmentSelector: { async selectEnvironment() { throw new Error('cancellation must stop before environment selection'); } },
      preparationAdapter: {
        async prepare() { throw new Error('cancellation must stop before preparation'); },
        async reconcile() { throw new Error('cancellation must stop before reconciliation'); },
        async fence() { throw new Error('cancellation must stop before fencing a new preparation'); },
      },
    }, { runId: good.runId, taskIndex: 1, claimId: good.claimId }),
    (error: { code?: string }) => error.code === 'RUN_TASK_PREDECESSOR_NOT_TERMINAL',
    'the cancelled run cannot start a successor preparation after the gap is closed');

    const corrupt = await addFixture(client, { multiTask: true, overallDeadlineSecondsFromNow: 3600 });
    const corruptCompletionDeps = {
      ...completionDeps,
      taskReleaseSource: {
        async getActiveAdmissionRelease() { return null; },
        async getValidatedReleaseRecord(identity: string, manifestHash: string) {
          return identity === corrupt.record.releaseIdentity && manifestHash === corrupt.record.manifestHash
            ? corrupt.record as never : null;
        },
      } satisfies TaskReleaseQuerySource,
      evidenceSource: { async load(input: { runId: string; taskIndex: number; closureId: string }) {
        return input.runId === corrupt.runId && input.taskIndex === 0 && input.closureId === corrupt.closureId
          ? structuredClone(corrupt.evaluationInput) as EvaluateTaskInput : null;
      } },
    };
    await finalizeKnownTrainingTask(corruptCompletionDeps, { runId: corrupt.runId, taskIndex: 0 });
    const successor = corrupt.record.manifest.cases.training.find((entry: { taskId: string }) => entry.taskId === 'S2');
    assert.ok(successor);
    await client`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
        release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,
        environment_manifest_sha256,application_source_hash)
      VALUES(${randomUUID()},${corrupt.runId},1,${corrupt.claimId},${randomUUID()},'orphan-successor-preparation',
        ${corrupt.record.releaseIdentity},${corrupt.record.manifestHash},'S2',${successor.caseId},${successor.caseHash},
        ${successor.initialState.stateSha256},${corrupt.record.manifest.executionIdentityHash},
        ${corrupt.record.manifest.executionIdentity.environmentManifestSha256},${corrupt.record.manifest.executionIdentity.x402ServiceSha256})`;
    await assert.rejects(requestRunCancellation(db, {
      ownerId: corrupt.ownerId, runId: corrupt.runId, operationId: `cancelgap_${randomUUID().replaceAll('-', '')}`,
      reason: 'owner_voluntary',
    }), (error: { code?: string }) => error.code === 'TASK_PREPARATION_AMBIGUOUS',
    'an orphaned intent without its exact lease and observation cannot be used as a cancellation fence');
    const untouched = await client`SELECT r.status,
        (SELECT count(*)::int FROM oid_run_outbox WHERE run_id=r.id AND event_type='run.cancel.requested') AS cancel_outbox_count,
        rr.state AS reservation_state,h.state AS budget_state,c.status AS claim_status,
        (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slot_count
      FROM oid_benchmark_run r JOIN oid_run_reservation rr ON rr.run_id=r.id
      JOIN oid_run_budget_hold h ON h.run_id=r.id JOIN oid_run_dispatch_claim c ON c.run_id=r.id WHERE r.id=${corrupt.runId}`;
    assert.deepEqual(untouched[0], { status: 'running', cancel_outbox_count: 0, reservation_state: 'debited',
      budget_state: 'charged', claim_status: 'claimed', slot_count: 1 },
    'missing predecessor fence data retains the running claim, slot, charge, and reservation state');
  } finally {
    await client.end();
    await admin.end();
  }
});
