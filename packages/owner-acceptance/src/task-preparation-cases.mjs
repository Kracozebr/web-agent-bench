/**
 * Real isolated PostgreSQL persistence/race invariants for task preparation.
 * All executor, selector, release verifier, and evidence ports here are synthetic test doubles;
 * this case does not prepare a BEF environment or prove actual execution readiness.
 */
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { seedActionRun } from './task-action-cases.mjs';
import { createSyntheticTaskPreparationReleaseFixture } from './task-store-cases.mjs';

const hash = (value) => createHash('sha256').update(String(value)).digest('hex');
const key = () => randomUUID();
const evidence = (name) => ({ path: `artifacts/runs/synthetic-task-preparation/${name}.json`, sha256: hash(name),
  boundary: 'actual_tool_http_x402_local_evm_application_store' });
function errorHasCode(error, expectedCode) {
  const pending = [error];
  const visited = new Set();
  while (pending.length) {
    const current = pending.pop();
    if (!current || (typeof current !== 'object' && typeof current !== 'function') || visited.has(current)) continue;
    visited.add(current);
    if (current.code === expectedCode) return true;
    for (const key of ['cause', 'originalError', 'driverError', 'parent']) {
      if (current[key]) pending.push(current[key]);
    }
  }
  return false;
}
function evidenceWithPathLength(length, name) {
  const prefix = 'artifacts/runs/';
  const suffix = '.json';
  const path = `${prefix}${'x'.repeat(length - prefix.length - suffix.length)}${suffix}`;
  assert.equal(path.length, length);
  return { path, sha256: hash(name), boundary: 'actual_tool_http_x402_local_evm_application_store' };
}

async function insertSyntheticReadyObservation(setup, preparation, result, fixtureEvidence, baselineEvidence) {
  await setup.query(`INSERT INTO oid_task_preparation_observation(
      preparation_id,revision,status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence)
    VALUES($1,2,'ready',$2,$3,$4,$5,$6::jsonb,$7::jsonb)`, [
    preparation.intent.preparationId, result.generationId, result.participantId, result.payerAddress, result.initialStateSha256,
    JSON.stringify(fixtureEvidence), JSON.stringify(baselineEvidence),
  ]);
}

async function seedPreparingRun(setup, candidate) {
  const run = await seedActionRun(setup, { taskId: 'S2', mode: 'training', createExecutionContext: false });
  const manifest = candidate;
  const trainingTaskIds = ['S2'];
  await setup.query(`UPDATE oid_run_launch_intent SET task_ids=$2::text[],release_identity=$3,benchmark_version=$4,
      manifest_hash=$5,benchmark_hash=$6,policy_hash=$7 WHERE id=(SELECT intent_id FROM oid_benchmark_run WHERE id=$1)`,
  [run.runId, trainingTaskIds, manifest.releaseIdentity, manifest.benchmarkVersion, manifest.manifestHash, manifest.benchmarkHash, manifest.policyHash]);
  await setup.query(`UPDATE oid_benchmark_run SET status='preparing',task_ids=$2::text[],release_identity=$3,
      benchmark_version=$4,manifest_hash=$5,benchmark_hash=$6,policy_hash=$7,started_at=NULL,overall_deadline=NULL,
      environment_id=NULL,environment_evidence_hash=NULL WHERE id=$1`,
  [run.runId, trainingTaskIds, manifest.releaseIdentity, manifest.benchmarkVersion, manifest.manifestHash, manifest.benchmarkHash, manifest.policyHash]);
  await setup.query(`UPDATE oid_run_task SET task_id='S2',status='queued',snapshot_json='{}'::jsonb,started_at=NULL,
      deadline_at=NULL,finished_at=NULL WHERE run_id=$1 AND task_index=0`, [run.runId]);
  const claimId = key();
  await setup.query(`INSERT INTO oid_run_dispatch_claim(run_id,owner_id,agent_id,claim_id,turn_number,status,claimed_at)
      VALUES($1,$2,$3,$4,1,'claimed',clock_timestamp())`, [run.runId, run.ownerId, run.agentId, claimId]);
  await setup.query(`INSERT INTO oid_run_execution_slot(agent_id,owner_id,run_id,claim_id,state,acquired_at)
      VALUES($1,$2,$3,$4,'preparing',clock_timestamp())`, [run.agentId, run.ownerId, run.runId, claimId]);
  return { ...run, claimId };
}

function readyResult(preparation, generationId = key()) {
  return {
    environmentId: preparation.intent.environmentId,
    generationId,
    manifestHash: preparation.intent.manifestHash,
    applicationSourceHash: preparation.intent.applicationSourceHash,
    environmentManifestSha256: preparation.intent.environmentManifestSha256,
    initialStateSha256: preparation.intent.initialStateSha256,
    participantId: `synthetic-participant-${generationId}`,
    payerAddress: `0x${'1'.repeat(40)}`,
    fixtureEvidence: evidence(`fixture-${generationId}`),
    baselineEvidence: evidence(`baseline-${generationId}`),
  };
}

export async function runTaskPreparationCases({ databaseUrl, observerDatabaseUrl }) {
  const ownerUrl = new URL(databaseUrl), observerUrl = new URL(observerDatabaseUrl);
  assert.equal(ownerUrl.hostname, 'postgres');
  assert.equal(observerUrl.hostname, 'postgres');
  assert.equal(ownerUrl.username, 'oid_owner');
  assert.equal(observerUrl.username, 'oid_observer');
  assert.match(ownerUrl.pathname, /^\/oid_acceptance_[a-f0-9]{32}$/);
  assert.equal(ownerUrl.pathname, observerUrl.pathname);
  const [{ createDatabase }, { loadConfig }, releaseApi, storeApi, preparationApi] = await Promise.all([
    import('../../owner-identity/dist/db.js'), import('../../owner-identity/dist/config.js'),
    import('../../owner-identity/dist/task-release.js'), import('../../owner-identity/dist/task-store.js'),
    import('../../owner-identity/dist/task-preparation.js'),
  ]);
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 3, application_name: 'synthetic-task-preparation-setup' });
  const observer = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: 'synthetic-task-preparation-observer' });
  const { db, client } = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl }));
  try {
    const role = (await observer.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly")).rows[0];
    assert.deepEqual(role, { role: 'oid_observer', readonly: 'on' });
    const beforeLedger = (await observer.query('SELECT count(*)::int AS count FROM oid_ledger_entry')).rows[0].count;
    const { candidate, verifier } = createSyntheticTaskPreparationReleaseFixture(releaseApi);
    const activated = await storeApi.activatePostgresTaskReleaseCandidate(db, candidate, verifier);
    assert.equal(activated.status, 'validated', 'synthetic verifier should seed only the database contract fixture');
    const releaseSource = storeApi.createPostgresTaskReleaseQuerySource(db);
    const selectedEnvironments = new Map();
    const adapterOutcomes = new Map();
    const prepareCalls = new Map();
    const reconcileCalls = new Map();
    const adapterFailures = new Set();
    const fenceOverrides = new Map();
    const deps = {
      db, releaseSource,
      environmentSelector: {
        async selectEnvironment({ runId }) {
          const environmentId = selectedEnvironments.get(runId) ?? 'synthetic-owner-preparation-env';
          selectedEnvironments.set(runId, environmentId);
          return environmentId;
        },
      },
      preparationAdapter: {
        async prepare({ intent }) {
          prepareCalls.set(intent.preparationId, (prepareCalls.get(intent.preparationId) ?? 0) + 1);
          await new Promise((resolve) => setTimeout(resolve, 25));
          if (adapterFailures.has(intent.preparationId)) throw new Error('synthetic adapter response lost after dispatch');
          return adapterOutcomes.get(intent.preparationId) ?? { status: 'unknown', generationId: null, reasonCode: 'adapter_outcome_unknown' };
        },
        async reconcile({ intent, generationId }) {
          reconcileCalls.set(intent.preparationId, (reconcileCalls.get(intent.preparationId) ?? 0) + 1);
          return adapterOutcomes.get(intent.preparationId) ?? { status: 'unknown', generationId, reasonCode: 'restart_reconciliation_required' };
        },
        async fence({ intent, generationId }) {
          return fenceOverrides.get(intent.preparationId) ?? {
            confirmed: true, preparationId: intent.preparationId, leaseId: intent.leaseId,
            environmentId: intent.environmentId, generationId, evidence: evidence(`fence-${intent.preparationId}`),
          };
        },
      },
    };

    const firstRun = await seedPreparingRun(setup, candidate);
    const target = { runId: firstRun.runId, taskIndex: 0, claimId: firstRun.claimId };
    const concurrent = await Promise.all(Array.from({ length: 6 }, () => preparationApi.beginTaskPreparation(deps, {
      ...target, caseHash: 'f'.repeat(64), environmentManifestSha256: 'e'.repeat(64),
    })));
    assert.equal(concurrent.filter((row) => !row.replayed).length, 1, 'concurrent exact claims create one durable preparation');
    const preparation = concurrent[0].preparation;
    assert.ok(concurrent.every((row) => row.preparation.intent.preparationId === preparation.intent.preparationId));
    const sealedCase = candidate.cases.training.find((entry) => entry.taskId === 'S2');
    assert.equal(preparation.intent.caseHash, sealedCase.caseHash, 'case hash comes from the validated sealed manifest');
    assert.equal(preparation.intent.initialStateSha256, sealedCase.initialState.stateSha256);
    assert.equal(preparation.intent.applicationSourceHash, candidate.executionIdentity.x402ServiceSha256);
    assert.equal(preparation.intent.environmentManifestSha256, candidate.executionIdentity.environmentManifestSha256);
    assert.equal((await observer.query('SELECT count(*)::int AS count FROM oid_task_preparation_intent WHERE run_id=$1', [target.runId])).rows[0].count, 1);
    assert.equal((await observer.query('SELECT count(*)::int AS count FROM oid_task_environment_lease WHERE preparation_id=$1', [preparation.intent.preparationId])).rows[0].count, 1);
    await assert.rejects(preparationApi.beginTaskPreparation(deps, { ...target, claimId: key() }), (error) => error.code === 'STALE_RUN_CLAIM');

    const result = readyResult(preparation);
    adapterOutcomes.set(preparation.intent.preparationId, { status: 'prepared', result: { ...result, initialStateSha256: hash('wrong-baseline') } });
    await Promise.all(Array.from({ length: 6 }, () => preparationApi.prepareTaskExecution(deps, target)));
    assert.equal(prepareCalls.get(preparation.intent.preparationId), 1, 'only one concurrent caller wins the durable dispatch claim');
    assert.equal((await preparationApi.getTaskPreparation(db, preparation.intent.preparationId)).dispatchStatus, 'unknown');
    const baselineMismatch = await preparationApi.getTaskPreparation(db, preparation.intent.preparationId);
    assert.equal(baselineMismatch.observation.status, 'unknown');
    assert.equal(baselineMismatch.observation.generationId, result.generationId);
    assert.equal(baselineMismatch.observation.reasonCode, 'baseline_state_mismatch');
    adapterOutcomes.set(preparation.intent.preparationId, { status: 'prepared', result: { ...result, generationId: key() } });
    const wrongGeneration = await preparationApi.prepareTaskExecution(deps, target);
    assert.equal(wrongGeneration.observation.status, 'unknown');
    assert.equal(wrongGeneration.observation.generationId, result.generationId, 'reconciliation preserves the first known generation');
    adapterOutcomes.set(preparation.intent.preparationId, { status: 'prepared', result });
    const reconciled = await preparationApi.prepareTaskExecution(deps, target);
    assert.equal(reconciled.observation.status, 'ready');
    assert.equal((await preparationApi.assertTaskPreparationReady(db, target)).intent.preparationId, preparation.intent.preparationId);
    await assert.rejects(setup.query(`INSERT INTO oid_task_preparation_observation(
        preparation_id,revision,status,generation_id,participant_id,payer_address,baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES($1,5,'ready',$2,'changed-participant',$3,$4,$5::jsonb,$6::jsonb)`, [
      preparation.intent.preparationId, result.generationId, result.payerAddress, result.initialStateSha256,
      JSON.stringify(result.fixtureEvidence), JSON.stringify(result.baselineEvidence),
    ]), (error) => error.code === '23514', 'a repeated ready observation cannot rewrite public identity or evidence');

    await setup.query(`UPDATE oid_benchmark_run SET status='running',started_at=clock_timestamp(),overall_deadline=clock_timestamp()+interval '1 hour'
      WHERE id=$1`, [target.runId]);
    await setup.query(`UPDATE oid_run_task SET status='active',started_at=clock_timestamp(),deadline_at=clock_timestamp()+interval '10 minutes'
      WHERE run_id=$1 AND task_index=0`, [target.runId]);
    await setup.query("UPDATE oid_run_execution_slot SET state='running' WHERE run_id=$1", [target.runId]);
    await assert.rejects(preparationApi.beginTaskPreparation(deps, target), (error) => error.code === 'TASK_PREPARATION_RUN_NOT_CURRENT');
    await assert.rejects(preparationApi.assertTaskPreparationReady(db, target), (error) => error.code === 'TASK_PREPARATION_RUN_NOT_CURRENT');
    await setup.query("UPDATE oid_benchmark_run SET status='cancelled',finished_at=clock_timestamp(),terminal_reason='test_cancel' WHERE id=$1", [target.runId]);
    await assert.rejects(preparationApi.assertTaskPreparationReady(db, target), (error) => error.code === 'TASK_PREPARATION_RUN_NOT_CURRENT');
    await assert.rejects(preparationApi.beginTaskPreparation(deps, target), (error) => error.code === 'TASK_PREPARATION_RUN_NOT_CURRENT');
    fenceOverrides.set(preparation.intent.preparationId, {
      confirmed: true, preparationId: preparation.intent.preparationId, leaseId: key(),
      environmentId: preparation.intent.environmentId, generationId: result.generationId, evidence: evidence('fence-wrong-lease'),
    });
    await assert.rejects(preparationApi.fenceTaskPreparation(deps, preparation.intent.preparationId), (error) => error.code === 'TASK_ENVIRONMENT_FENCE_MISMATCH');
    fenceOverrides.delete(preparation.intent.preparationId);
    assert.deepEqual(await preparationApi.fenceTaskPreparation(deps, preparation.intent.preparationId), { released: true, replayed: false });
    assert.deepEqual(await preparationApi.fenceTaskPreparation(deps, preparation.intent.preparationId), { released: true, replayed: true });

    const unknownRun = await seedPreparingRun(setup, candidate);
    const unknownTarget = { runId: unknownRun.runId, taskIndex: 0, claimId: unknownRun.claimId };
    const unknownPrep = (await preparationApi.beginTaskPreparation(deps, unknownTarget)).preparation;
    adapterFailures.add(unknownPrep.intent.preparationId);
    const firstUnknown = await preparationApi.prepareTaskExecution(deps, unknownTarget);
    assert.equal(firstUnknown.observation.status, 'unknown');
    assert.equal(firstUnknown.observation.generationId, null);
    assert.equal(firstUnknown.observation.reasonCode, 'adapter_call_failed');
    assert.equal(firstUnknown.dispatchStatus, 'unknown');
    adapterFailures.delete(unknownPrep.intent.preparationId);
    adapterOutcomes.set(unknownPrep.intent.preparationId, { status: 'prepared', result: readyResult(unknownPrep) });
    const unrecoverableUnknown = await preparationApi.prepareTaskExecution(deps, unknownTarget);
    assert.equal(unrecoverableUnknown.observation.status, 'unknown', 'an unknown generation cannot be inferred by a later adapter response');
    assert.equal(unrecoverableUnknown.observation.generationId, null);
    assert.equal(prepareCalls.get(unknownPrep.intent.preparationId), 1, 'a response-loss retry never repeats the external prepare call');
    assert.equal(reconcileCalls.get(unknownPrep.intent.preparationId) ?? 0, 0, 'unknown without original generation is not reconciled by creating a replacement');
    await preparationApi.fenceTaskPreparation(deps, unknownPrep.intent.preparationId);

    const successorRun = await seedPreparingRun(setup, candidate);
    const successorTarget = { runId: successorRun.runId, taskIndex: 0, claimId: successorRun.claimId };
    const successor = (await preparationApi.beginTaskPreparation(deps, successorTarget)).preparation;
    assert.equal(successor.intent.environmentId, unknownPrep.intent.environmentId, 'fenced environment may receive a successor lease');
    fenceOverrides.set(unknownPrep.intent.preparationId, {
      confirmed: true, preparationId: unknownPrep.intent.preparationId, leaseId: unknownPrep.intent.leaseId,
      environmentId: unknownPrep.intent.environmentId, generationId: null, evidence: evidence('stale-callback-different-receipt'),
    });
    await assert.rejects(preparationApi.fenceTaskPreparation(deps, unknownPrep.intent.preparationId), (error) => error.code === 'TASK_ENVIRONMENT_FENCE_IMMUTABLE');
    fenceOverrides.delete(unknownPrep.intent.preparationId);
    assert.equal((await preparationApi.getTaskPreparation(db, successor.intent.preparationId)).leaseStatus, 'leased',
      'stale prior lease callback cannot release the successor lease');

    const reusedGeneration = key();
    adapterOutcomes.set(successor.intent.preparationId, { status: 'unknown', generationId: reusedGeneration, reasonCode: 'adapter_outcome_unknown' });
    await preparationApi.prepareTaskExecution(deps, successorTarget);
    await preparationApi.fenceTaskPreparation(deps, successor.intent.preparationId);
    const reusedRun = await seedPreparingRun(setup, candidate);
    const reusedTarget = { runId: reusedRun.runId, taskIndex: 0, claimId: reusedRun.claimId };
    const reusedPrep = (await preparationApi.beginTaskPreparation(deps, reusedTarget)).preparation;
    adapterOutcomes.set(reusedPrep.intent.preparationId, { status: 'unknown', generationId: reusedGeneration, reasonCode: 'adapter_outcome_unknown' });
    let reusedGenerationError;
    try {
      await preparationApi.prepareTaskExecution(deps, reusedTarget);
    } catch (error) {
      reusedGenerationError = error;
    }
    assert.ok(reusedGenerationError, 'one generation identity cannot be replayed into a foreign preparation');
    assert.ok(errorHasCode(reusedGenerationError, '23505'),
      'foreign generation reuse is rejected by the database uniqueness guard');
    const generationBindings = await observer.query(`SELECT generation_id,preparation_id,environment_id
      FROM oid_task_preparation_generation WHERE generation_id=$1 OR preparation_id=$2`,
    [reusedGeneration, reusedPrep.intent.preparationId]);
    assert.deepEqual(generationBindings.rows.map((row) => row.preparation_id), [successor.intent.preparationId],
      'the original generation binding remains unchanged and is not copied to the foreign preparation');
    assert.equal(generationBindings.rows[0].generation_id, reusedGeneration);
    assert.equal(generationBindings.rows[0].environment_id, successor.intent.environmentId);
    const rejectedObservation = await observer.query(`SELECT revision,status,generation_id
      FROM oid_task_preparation_observation WHERE preparation_id=$1 ORDER BY revision DESC LIMIT 1`,
    [reusedPrep.intent.preparationId]);
    assert.deepEqual(rejectedObservation.rows, [{ revision: 1, status: 'preparing', generation_id: null }],
      'the foreign generation collision leaves no durable generation observation for the rejected preparation');
    const rejectedDispatch = await observer.query(`SELECT state FROM oid_task_preparation_dispatch WHERE preparation_id=$1`,
      [reusedPrep.intent.preparationId]);
    assert.deepEqual(rejectedDispatch.rows, [{ state: 'dispatching' }],
      'the failed persistence transaction does not falsely settle the dispatch');
    const rejectedPreparation = await preparationApi.getTaskPreparation(db, reusedPrep.intent.preparationId);
    assert.equal(rejectedPreparation.observation.status, 'preparing', 'the foreign generation cannot make the new preparation ready');
    assert.equal(rejectedPreparation.observation.generationId, null);
    await preparationApi.fenceTaskPreparation(deps, reusedPrep.intent.preparationId);

    const maxPathRun = await seedPreparingRun(setup, candidate);
    const maxPathTarget = { runId: maxPathRun.runId, taskIndex: 0, claimId: maxPathRun.claimId };
    const maxPathPreparation = (await preparationApi.beginTaskPreparation(deps, maxPathTarget)).preparation;
    const maxPathResult = readyResult(maxPathPreparation);
    await insertSyntheticReadyObservation(setup, maxPathPreparation, maxPathResult,
      evidenceWithPathLength(512, 'max-path-fixture'), evidenceWithPathLength(512, 'max-path-baseline'));
    assert.equal((await preparationApi.assertTaskPreparationReady(db, maxPathTarget)).observation.status, 'ready',
      'hash-backed raw evidence paths at the declared 512 character limit are accepted');
    await preparationApi.fenceTaskPreparation(deps, maxPathPreparation.intent.preparationId);

    const longPathRun = await seedPreparingRun(setup, candidate);
    const longPathTarget = { runId: longPathRun.runId, taskIndex: 0, claimId: longPathRun.claimId };
    const longPathPreparation = (await preparationApi.beginTaskPreparation(deps, longPathTarget)).preparation;
    const longPathResult = readyResult(longPathPreparation);
    await assert.rejects(insertSyntheticReadyObservation(setup, longPathPreparation, longPathResult,
      evidenceWithPathLength(513, 'overlong-path-fixture'), evidenceWithPathLength(512, 'max-path-baseline')),
    (error) => error.code === '23514', 'a raw evidence path exceeding 512 characters is rejected by PostgreSQL');
    assert.equal((await preparationApi.getTaskPreparation(db, longPathPreparation.intent.preparationId)).observation.status, 'preparing');
    await preparationApi.fenceTaskPreparation(deps, longPathPreparation.intent.preparationId);

    const sensitiveColumns = await observer.query(`SELECT table_name,column_name FROM information_schema.columns
      WHERE table_schema='public' AND table_name IN ('oid_task_preparation_intent','oid_task_preparation_observation','oid_task_environment_lease')
        AND column_name ~* '(token|secret|private.?key|seed)'`);
    assert.deepEqual(sensitiveColumns.rows, [], 'preparation persistence contains only public identities and evidence refs');
    const afterLedger = (await observer.query('SELECT count(*)::int AS count FROM oid_ledger_entry')).rows[0].count;
    assert.equal(afterLedger, beforeLedger, 'preparation persistence never debits or funds a run');
    return {
      status: 'passed', boundary: 'synthetic_owner_task_preparation_postgresql_only',
      adapterClassification: 'synthetic_test_double_no_bef_or_fork_call',
      observations: [
        'concurrent_same_claim_one_intent_and_exclusive_lease', 'sealed_release_case_and_environment_pins_derived_server_side',
        'wrong_claim_rejected', 'one_durable_dispatch_per_preparation', 'unknown_known_generation_reconciles_same_generation_only',
        'response_loss_retry_never_repeats_external_prepare',
        'unknown_without_generation_never_becomes_ready', 'ready_identity_and_raw_evidence_are_immutable',
        'no_post_start_baseline_preparation', 'cancelled_run_preparation_cannot_be_consumed_or_replayed', 'lease_release_requires_exact_confirmed_fence',
        'stale_fence_callback_cannot_release_successor_lease', 'foreign_generation_reuse_rejected',
        '512_character_raw_reference_path_accepted_513_rejected',
        'no_secret_columns_or_ledger_effects',
      ],
      fullScenarioAcceptance: false,
    };
  } finally {
    await client.end();
    await setup.end();
    await observer.end();
  }
}
