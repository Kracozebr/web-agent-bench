import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { finalizeExhaustedBetaPlatformFailure, type BetaPlatformRecoveryAuthority } from './beta-platform-recovery.js';

const enabled = process.env.OID_BETA_PLATFORM_RECOVERY_PG_TEST === '1';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

function testOnlyAuthority(input: {
  runId: string; actionId: string; environmentId: string; operationId: string; payloadHash: string; evidenceHash: string;
}): BetaPlatformRecoveryAuthority {
  // AICODE-NOTE: This injected authority supplies preverified fixture facts only; it does not implement or prove a trusted production monitor.
  return {
    async verifyIncident() { return null; },
    async verifyOperation() { return null; },
    async verifyExhaustion() { return { ...input, source: 'beta_platform_monitor' }; },
  };
}

test('platform refund commits exactly once in isolated PostgreSQL and replays after concurrent calls and reconnect', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The pinned Docker runtime must provide its private owner database URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'This regression must run inside the isolated owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const observerUrlValue = process.env.OID_OBSERVER_DATABASE_URL;
  assert.ok(observerUrlValue, 'The pinned Docker runtime must provide its private read-only observer URL');
  const observerUrl = new URL(observerUrlValue);
  assert.equal(observerUrl.hostname, 'postgres');
  assert.equal(observerUrl.username, 'oid_observer');
  assert.equal(observerUrl.pathname, '/owner_identity');

  const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
  assert.match(databaseName, /^oid_acceptance_[a-f0-9]{32}$/);
  const targetUrl = new URL(sourceUrlValue);
  targetUrl.pathname = `/${databaseName}`;
  observerUrl.pathname = `/${databaseName}`;
  const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
  let client = postgres(targetUrl.toString(), { max: 8, connect_timeout: 10 });
  let observerClient: ReturnType<typeof postgres> | undefined;
  const db = drizzle(client) as unknown as OwnerDatabase;

  try {
    await admin.unsafe(`CREATE DATABASE ${databaseName} TEMPLATE template0`);
    const setup = postgres(targetUrl.toString(), { max: 1, connect_timeout: 10 });
    try {
      await admin.unsafe(`GRANT CONNECT ON DATABASE ${databaseName} TO oid_observer`);
      await setup.unsafe('GRANT USAGE ON SCHEMA public TO oid_observer');
      await setup.unsafe('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
    } finally { await setup.end(); }
    const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], {
      cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: targetUrl.toString() }, encoding: 'utf8',
    });
    assert.equal(migration.status, 0,
      `The fresh recovery acceptance database must migrate: ${migration.stderr || migration.stdout}`);
    const grantExistingTables = postgres(targetUrl.toString(), { max: 1, connect_timeout: 10 });
    try { await grantExistingTables.unsafe('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer'); }
    finally { await grantExistingTables.end(); }
    observerClient = postgres(observerUrl.toString(), { max: 2, connect_timeout: 10 });
    console.log(JSON.stringify({ event: 'oid_platform_recovery_pg_database', databaseName, retainedForInspection: true }));

    const fixture = await addFixture(client);
    const actionId = randomUUID();
    const accessGrantId = randomUUID();
    const bonusGrantId = randomUUID();
    const operationId = `platform_original_${randomUUID().replaceAll('-', '')}`;
    const actionPayloadHash = sha256(`${fixture.runId}:original-action`);
    const incidentEvidenceHash = sha256(`${fixture.runId}:incident`);
    const fenceEvidenceHash = sha256(`${fixture.runId}:fence`);
    const exhaustionEvidenceHash = sha256(`${fixture.runId}:exhaustion`);
    const actionEvidenceHash = sha256(`${fixture.runId}:observed-action`);
    const refundOperationId = `runref_${fixture.runId.replaceAll('-', '')}`;
    const debitOperationId = `rundeb_${fixture.runId.replaceAll('-', '')}`;

    await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
      VALUES(${accessGrantId},${fixture.ownerId},${fixture.agentId},${`grant_${randomUUID().replaceAll('-', '')}`},
        'https://example.invalid/api/agent','agent',1,clock_timestamp()+interval '1 day')`;
    await client`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,
        environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json)
      VALUES(${actionId},${fixture.runId},0,${fixture.ownerId},${fixture.agentId},1,${accessGrantId},'S1',${fixture.environmentId},
        1,${operationId},${actionPayloadHash},'inspect_catalog','{}'::jsonb)`;
    await client`INSERT INTO oid_run_task_action_outbox(action_id,status,delivered_at)
      VALUES(${actionId},'delivered',clock_timestamp())`;
    await client`INSERT INTO oid_run_task_action_receipt(action_id,receipt_revision,receipt_status,evidence_hash,updated_at)
      VALUES(${actionId},1,'observed',${actionEvidenceHash},clock_timestamp())`;

    await client`UPDATE oid_benchmark_run SET status='cancelled',terminal_reason='coordinator_platform_failure',
        cancellation_reason='coordinator_platform_failure',cancellation_evidence_hash=${fenceEvidenceHash}
      WHERE id=${fixture.runId}`;
    const nextSequence = await client`SELECT COALESCE(MAX(sequence),0)+1 AS sequence FROM oid_run_event WHERE run_id=${fixture.runId}`;
    const firstEventSequence = Number(nextSequence[0]?.sequence ?? 1);
    const cancelledPayload = { reason: 'coordinator_platform_failure', fenceEvidenceHash };
    await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      VALUES(${randomUUID()},${fixture.runId},${firstEventSequence},'worker','run.cancelled.after_start',
        ${sha256(JSON.stringify(cancelledPayload))},${JSON.stringify(cancelledPayload)}::jsonb)`;
    const recoveryStartedPayload = { actionId, operationId, incidentEvidenceHash,
      deadlineAt: new Date(Date.now() - 60_000).toISOString() };
    await client`INSERT INTO oid_run_event(id,run_id,sequence,source,event_type,payload_hash,payload_json)
      VALUES(${randomUUID()},${fixture.runId},${firstEventSequence + 1},'worker','run.platform_recovery_started',
        ${sha256(JSON.stringify(recoveryStartedPayload))},${JSON.stringify(recoveryStartedPayload)}::jsonb)`;

    await client`INSERT INTO oid_run_platform_recovery(action_id,run_id,owner_id,agent_id,task_index,environment_id,
        operation_id,payload_hash,incident_evidence_hash,started_at,deadline_at,clock_excluded_ms,status,latest_evidence_hash)
      VALUES(${actionId},${fixture.runId},${fixture.ownerId},${fixture.agentId},0,${fixture.environmentId},${operationId},
        ${actionPayloadHash},${incidentEvidenceHash},clock_timestamp()-interval '10 minutes',
        clock_timestamp()-interval '7 minutes',0,'recovered',${actionEvidenceHash})`;

    await client`INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id,created_at)
      VALUES(${bonusGrantId},${fixture.ownerId},250,${fixture.ownerId},'synthetic isolated recovery fixture',
        ${`bonus_${randomUUID().replaceAll('-', '')}`},clock_timestamp())`;
    await client`INSERT INTO oid_ledger_entry(id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,
        amount_units,available_delta_units,reserved_delta_units,expired_delta_units,reason)
      VALUES(${randomUUID()},${fixture.ownerId},${fixture.ownerId},${bonusGrantId},${`grant_${randomUUID().replaceAll('-', '')}`},
        'bonus_grant','tester_bonus',250,250,0,0,'synthetic isolated recovery fixture')`;
    await client`INSERT INTO oid_run_reservation(id,run_id,owner_id,source_kind,bonus_grant_id,amount_units,state,created_at,changed_at)
      VALUES(${randomUUID()},${fixture.runId},${fixture.ownerId},'tester_bonus',${bonusGrantId},250,'debited',clock_timestamp(),clock_timestamp())`;
    await client`INSERT INTO oid_ledger_entry(id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,
        amount_units,available_delta_units,reserved_delta_units,expired_delta_units,reason)
      VALUES(${randomUUID()},${fixture.ownerId},${fixture.ownerId},${bonusGrantId},${debitOperationId},'debit','tester_bonus',
        250,0,-250,0,'synthetic isolated recovery fixture')`;

    const before = await client`SELECT run.status AS run_status,recovery.status AS recovery_status,
        (SELECT count(*)::int FROM oid_run_platform_refund WHERE run_id=${fixture.runId}) AS refund_rows,
        (SELECT count(*)::int FROM oid_ledger_entry WHERE operation_id LIKE ${`${refundOperationId}_%`} AND entry_type='refund') AS refund_entries
      FROM oid_benchmark_run run JOIN oid_run_platform_recovery recovery ON recovery.run_id=run.id WHERE run.id=${fixture.runId}`;
    assert.deepEqual(before[0], { run_status: 'cancelled', recovery_status: 'recovered', refund_rows: 0, refund_entries: 0 });

    const exhaustion = { runId: fixture.runId, actionId, environmentId: fixture.environmentId,
      operationId, payloadHash: actionPayloadHash, evidenceHash: exhaustionEvidenceHash };
    const badAuthority = testOnlyAuthority({ ...exhaustion, environmentId: 'wrong-environment' });
    await assert.rejects(
      finalizeExhaustedBetaPlatformFailure({ db, authority: badAuthority }, {
        runId: fixture.runId, actionId, exhaustionEvidence: { fixture: 'wrong lineage' },
      }),
      (error: unknown) => typeof error === 'object' && error !== null &&
        'code' in error && error.code === 'PLATFORM_RECOVERY_LINEAGE_MISMATCH',
      'a test-only authority that returns a mismatched environment must not settle the refund',
    );

    const authority = testOnlyAuthority(exhaustion);
    const concurrentResults = await Promise.all([
      finalizeExhaustedBetaPlatformFailure({ db, authority }, {
        runId: fixture.runId, actionId, exhaustionEvidence: { fixture: 'verified exhausted operation' },
      }),
      finalizeExhaustedBetaPlatformFailure({ db, authority }, {
        runId: fixture.runId, actionId, exhaustionEvidence: { fixture: 'verified exhausted operation' },
      }),
    ]);
    assert.deepEqual(concurrentResults.map((result) => result.replayed).sort(), [false, true]);
    assert.ok(concurrentResults.every((result) => result.status === 'failed' && result.bonusRefundedUnits === '250'));

    await client.end();
    client = postgres(targetUrl.toString(), { max: 8, connect_timeout: 10 });
    const restartedDb = drizzle(client) as unknown as OwnerDatabase;
    const afterReconnect = await finalizeExhaustedBetaPlatformFailure({ db: restartedDb, authority }, {
      runId: fixture.runId, actionId, exhaustionEvidence: { fixture: 'verified exhausted operation' },
    });
    assert.deepEqual(afterReconnect, { runId: fixture.runId, status: 'failed', bonusRefundedUnits: '250', replayed: true });

    const observerPrivileges = await observerClient`SELECT current_user,
        has_table_privilege(current_user,'oid_run_platform_recovery','SELECT') AS can_read_recovery,
        has_table_privilege(current_user,'oid_run_platform_recovery','UPDATE') AS can_update_recovery`;
    assert.deepEqual(observerPrivileges[0], { current_user: 'oid_observer', can_read_recovery: true, can_update_recovery: false });
    const settled = await observerClient.begin(async (tx) => {
      await tx.unsafe('SET TRANSACTION READ ONLY');
      return await tx`SELECT run.status AS run_status,run.terminal_reason,recovery.status AS recovery_status,
        recovery.latest_evidence_hash,
        (SELECT count(*)::int FROM oid_run_platform_refund WHERE run_id=${fixture.runId}) AS refund_rows,
        (SELECT count(*)::int FROM oid_ledger_entry WHERE operation_id LIKE ${`${refundOperationId}_%`} AND entry_type='refund') AS refund_entries,
        (SELECT COALESCE(sum(available_delta_units),0)::text FROM oid_ledger_entry
          WHERE operation_id LIKE ${`${refundOperationId}_%`} AND entry_type='refund') AS available_refund_units,
        (SELECT count(*)::int FROM oid_ledger_audit WHERE operation_id=${refundOperationId}
          AND event_type='run_platform_failure_refunded') AS audit_rows
      FROM oid_benchmark_run run JOIN oid_run_platform_recovery recovery ON recovery.run_id=run.id WHERE run.id=${fixture.runId}`;
    });
    assert.deepEqual(settled[0], {
      run_status: 'failed', terminal_reason: 'platform_failure_recovery_exhausted', recovery_status: 'refunded',
      latest_evidence_hash: exhaustionEvidenceHash, refund_rows: 1, refund_entries: 1,
      available_refund_units: '250', audit_rows: 1,
    });
    await assert.rejects(observerClient`UPDATE oid_benchmark_run SET status='running' WHERE id=${fixture.runId}`,
      /permission denied|read-only/i, 'the independent observer role must not be able to alter the settlement');
  } finally {
    await observerClient?.end();
    await client.end();
    await admin.end();
  }
});
