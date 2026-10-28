/** Real isolated PostgreSQL binding invariants; no BEF request or signing occurs. */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { seedActionRun } from './task-action-cases.mjs';

export async function runTaskExecutionBindingCases({ databaseUrl, observerDatabaseUrl }) {
  const ownerUrl = new URL(databaseUrl), observerUrl = new URL(observerDatabaseUrl);
  assert.equal(ownerUrl.hostname, 'postgres');
  assert.equal(observerUrl.hostname, 'postgres');
  assert.equal(ownerUrl.username, 'oid_owner');
  assert.equal(observerUrl.username, 'oid_observer');
  assert.match(ownerUrl.pathname, /^\/oid_acceptance_[a-f0-9]{32}$/);
  assert.equal(ownerUrl.pathname, observerUrl.pathname);
  const [{ createDatabase }, { loadConfig }, bindings] = await Promise.all([
    import('../../owner-identity/dist/db.js'), import('../../owner-identity/dist/config.js'),
    import('../../owner-identity/dist/task-execution-binding.js'),
  ]);
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 2, application_name: 'execution-binding-fixture' });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: 'execution-binding-observer' });
  const created = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  let restarted;
  try {
    const role = (await observer.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly")).rows[0];
    assert.deepEqual(role, { role: 'oid_observer', readonly: 'on' });
    const fixture = await seedActionRun(setup, { createBinding: false });
    await setup.query('UPDATE oid_benchmark_run SET environment_id=$2 WHERE id=$1', [fixture.runId, `compatibility-pointer-${fixture.runId}`]);
    const before = (await observer.query('SELECT count(*)::int AS count FROM oid_ledger_entry')).rows[0].count;
    const input = { runId: fixture.runId, taskIndex: 0, envId: fixture.environmentId,
      generationId: fixture.generationId, manifestHash: fixture.environmentManifestHash,
      applicationSourceHash: fixture.applicationSourceHash,
      participantId: fixture.participantId, payerAddress: fixture.payerAddress };
    const outcomes = await Promise.all(Array.from({ length: 6 }, () => bindings.ensureTaskExecutionBinding(created.db, input)));
    assert.equal(outcomes.filter((result) => !result.replayed).length, 1);
    assert.ok(outcomes.every((result) => result.binding.createdAt === outcomes[0].binding.createdAt));
    assert.deepEqual(await bindings.assertTaskExecutionBinding(created.db, input), outcomes[0].binding);
    for (const change of [{ generationId: randomUUID() }, { manifestHash: 'c'.repeat(64) },
      { applicationSourceHash: 'd'.repeat(64) }, { participantId: 'other' }, { payerAddress: `0x${'2'.repeat(40)}` }]) {
      await assert.rejects(bindings.ensureTaskExecutionBinding(created.db, { ...input, ...change }),
        (error) => error.code === 'TASK_EXECUTION_BINDING_MISMATCH');
      await assert.rejects(bindings.assertTaskExecutionBinding(created.db, { ...input, ...change }),
        (error) => error.code === 'TASK_EXECUTION_BINDING_MISMATCH');
    }
    restarted = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
    const replay = await bindings.ensureTaskExecutionBinding(restarted.db, { ...input,
      runId: input.runId.toUpperCase(), generationId: input.generationId.toUpperCase(),
      payerAddress: input.payerAddress.toUpperCase().replace('0X', '0x') });
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.binding, outcomes[0].binding);
    const competitor = await seedActionRun(setup, { createBinding: false });
    await assert.rejects(bindings.ensureTaskExecutionBinding(created.db, { ...input, runId: competitor.runId }),
      (error) => error.code === 'TASK_EXECUTION_BINDING_MISMATCH');
    assert.equal(await bindings.getTaskExecutionBinding(created.db, { runId: competitor.runId, taskIndex: 0 }), null);
    await assert.rejects(setup.query(`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,
      application_source_hash,participant_id,payer_address) VALUES($1,0,$2,$3,$4,$5,$6,$7)`,
    [competitor.runId, input.envId, input.generationId, input.manifestHash, input.applicationSourceHash, input.participantId, input.payerAddress]),
    (error) => error.code === '23505', 'the database still forbids one BEF generation from binding to two tasks');
    const expired = await seedActionRun(setup, { deadline: '-1 second', createBinding: false });
    await assert.rejects(bindings.ensureTaskExecutionBinding(created.db, { ...input, runId: expired.runId,
      envId: expired.environmentId, generationId: expired.generationId,
      manifestHash: expired.environmentManifestHash, applicationSourceHash: expired.applicationSourceHash,
      participantId: expired.participantId, payerAddress: expired.payerAddress }),
    (error) => error.code === 'TASK_EXECUTION_BINDING_CLOSED');
    await setup.query("UPDATE oid_run_task SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1", [fixture.runId]);
    assert.equal((await bindings.ensureTaskExecutionBinding(created.db, input)).replayed, true,
      'reading the original public pin after expiry cannot reset a deadline or generation');
    for (const statement of [
      'UPDATE oid_task_execution_binding SET generation_id=gen_random_uuid()',
      'DELETE FROM oid_task_execution_binding',
    ]) await assert.rejects(setup.query(statement), (error) => error.code === '55000');
    await assert.rejects(setup.query('TRUNCATE oid_task_execution_binding'), (error) => error.code === '0A000',
      'a plain truncate is blocked by the referencing observation-bundle foreign key');
    const truncateClient = await setup.connect();
    try {
      await truncateClient.query('BEGIN');
      try {
        await assert.rejects(truncateClient.query('TRUNCATE oid_task_execution_binding CASCADE'),
          (error) => error.code === '55000', 'the immutability trigger must reject cascade truncate');
      } finally {
        // If the trigger regresses and the statement succeeds, rollback restores every cascaded row.
        await truncateClient.query('ROLLBACK');
      }
    } finally { truncateClient.release(); }
    const retained = (await observer.query('SELECT * FROM oid_task_execution_binding WHERE run_id=$1', [fixture.runId])).rows;
    assert.equal(retained.length, 1);
    assert.equal(retained[0].generation_id, input.generationId);
    assert.equal(Object.keys(retained[0]).some((key) => /token|secret|signature|private_key/.test(key)), false);
    assert.equal((await observer.query('SELECT count(*)::int AS count FROM oid_ledger_entry')).rows[0].count, before);
    return { status: 'passed', fullScenarioAcceptance: false,
      boundary: 'Actual PostgreSQL public generation binding with synthetic isolated run fixtures; no RPC/signing',
      observations: ['concurrent_binding_once', 'public_identity_cannot_change', 'restart_keeps_original_generation',
        'generation_cannot_belong_to_another_task', 'expired_task_cannot_bind_new_generation',
        'public_binding_replay_does_not_reopen_deadline', 'binding_update_delete_truncate_denied',
        'no_tokens_or_keys_in_binding_store', 'binding_has_no_ledger_effects'],
      runIds: [fixture.runId, competitor.runId, expired.runId] };
  } finally {
    await restarted?.client.end();
    await created.client.end();
    await setup.end(); await observer.end();
  }
}
