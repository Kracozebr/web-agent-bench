import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { migrateTaskObservations } from './task-observation-migrate.js';
import { readSealedTaskObservationBundle, sealTaskObservationBundle, type TaskObservationBundleCandidate } from './task-observation-store.js';
import type { OwnerDatabase } from './db.js';
import type { TaskCase, TaskReleaseQuerySource } from './task-release.js';

const enabled = process.env.OID_TASK_OBSERVATION_STORE_PG_TEST === '1';

function hash(label: string): string {
  // Stable fixture digests; these values identify no external user or environment.
  return createHash('sha256').update(label).digest('hex');
}

const evidence = (label: string) => ({
  path: `synthetic-observation/${label}.json`,
  sha256: hash(label),
  boundary: 'actual_tool_http_x402_local_evm_application_store' as const,
});

test('isolated PostgreSQL observation journal retains exact bindings, idempotently, and immutably', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The Docker runtime entrypoint must provide the local owner DB URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres', 'This contract test must run inside the owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');

  const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
  const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
  const testUrl = new URL(sourceUrlValue);
  testUrl.pathname = `/${databaseName}`;
  const client = postgres(testUrl.toString(), { max: 6, connect_timeout: 10 });
  const db = drizzle(client) as unknown as OwnerDatabase;

  try {
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);
    const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], {
      cwd: '/workspace',
      env: { ...process.env, OID_DATABASE_URL: testUrl.toString() },
      encoding: 'utf8',
    });
    assert.equal(migration.status, 0, `isolated owner schema migration failed: ${migration.stderr || migration.stdout}`);
    await client.begin(async (tx) => migrateTaskObservations(tx));

    const userId = randomUUID(), ownerId = randomUUID(), agentId = randomUUID(), intentId = randomUUID();
    const runId = randomUUID(), closureId = randomUUID(), preparationId = randomUUID(), leaseId = randomUUID();
    const generationId = randomUUID(), claimId = randomUUID();
    const closureOperationId = randomUUID(), closurePayloadHash = hash('closure');
    const grantId = randomUUID(), actionId = randomUUID(), actionOperationId = randomUUID();
    const releaseIdentity = `synthetic-observation-${randomUUID().slice(0, 8)}`;
    const releaseManifestHash = hash('release-manifest');
    const environmentManifestHash = hash('environment-manifest');
    const applicationSourceHash = hash('application-source');
    const executionIdentityHash = hash('execution-identity');
    const initialStateSha256 = hash('initial-state');
    const caseId = 'synthetic-observation-S1';
    const caseHash = hash('case');
    const rubricHash = hash('rubric');
    const environmentId = `synthetic-observation-env-${randomUUID().slice(0, 8)}`;
    const successorEnvironmentId = `synthetic-successor-env-${randomUUID().slice(0, 8)}`;
    const taskCase = {
      taskId: 'S1', caseId, caseHash, rubricHash, executionIdentityHash,
      initialState: { stateSha256: initialStateSha256 },
    } as unknown as TaskCase;
    const manifest = { releaseIdentity, manifestHash: releaseManifestHash, cases: { training: [], ranked: [taskCase] } };
    const record = { releaseIdentity, manifestHash: releaseManifestHash, manifest };
    const taskReleaseSource: TaskReleaseQuerySource = {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord(identity, digest) {
        return identity === releaseIdentity && digest === releaseManifestHash ? record as never : null;
      },
    };

    await client`INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES(${userId},'Synthetic journal fixture',${`${userId}@example.invalid`},true)`;
    await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${ownerId},${userId},'admitted')`;
    await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agentId},${ownerId},'Synthetic journal agent')`;
    await client`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,expires_at)
      VALUES(${intentId},${ownerId},${agentId},${randomUUID()},${hash('intent')},'ranked',ARRAY['S1'],${releaseIdentity},'synthetic-v1',
        ${releaseManifestHash},${hash('benchmark')},${hash('policy')},0,0,1,1,clock_timestamp()+interval '1 hour')`;
    await client`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,
      benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queue_deadline,environment_id)
      VALUES(${runId},${intentId},${ownerId},${agentId},'ranked',ARRAY['S1'],${releaseIdentity},'synthetic-v1',${releaseManifestHash},
        ${hash('benchmark')},${hash('policy')},0,0,1,1,'running',clock_timestamp()+interval '1 hour',${successorEnvironmentId})`;
    await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES(${runId},0,'S1','active')`;
    await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
      VALUES(${grantId},${ownerId},${agentId},${randomUUID()},'synthetic-observation-resource','agent',1,clock_timestamp()+interval '1 hour')`;
    await client`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,environment_id,
      action_sequence,operation_id,payload_hash,action_kind,command_json)
      VALUES(${actionId},${runId},0,${ownerId},${agentId},1,${grantId},'S1',${environmentId},1,${actionOperationId},${hash('action')},
        'transfer','{"kind":"transfer"}'::jsonb)`;
    // The fixture deliberately leaves sequence 2 without an action row to test fail-closed binding.
    await client`UPDATE oid_run_task SET accepted_action_sequence=2,reconciled_action_sequence=2 WHERE run_id=${runId} AND task_index=0`;

    await client`INSERT INTO oid_task_preparation_intent(preparation_id,run_id,task_index,claim_id,lease_id,environment_id,
      release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,environment_manifest_sha256,application_source_hash)
      VALUES(${preparationId},${runId},0,${claimId},${leaseId},${environmentId},${releaseIdentity},${releaseManifestHash},'S1',${caseId},
        ${caseHash},${initialStateSha256},${executionIdentityHash},${environmentManifestHash},${applicationSourceHash})`;
    await client`INSERT INTO oid_task_environment_lease(lease_id,preparation_id,environment_id,state)
      VALUES(${leaseId},${preparationId},${environmentId},'leased')`;
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,baseline_state_sha256)
      VALUES(${preparationId},1,'preparing',${generationId},${initialStateSha256})`;
    await client`INSERT INTO oid_task_execution_binding(run_id,task_index,env_id,generation_id,manifest_hash,application_source_hash,
      participant_id,payer_address) VALUES(${runId},0,${environmentId},${generationId},${environmentManifestHash},${applicationSourceHash},
      'synthetic-participant','0x1111111111111111111111111111111111111111')`;

    const taskObservationCandidate: TaskObservationBundleCandidate = {
      schemaVersion: 'bts-task-observation-bundle-candidate/v1', observationCutoffSequence: 4,
      cutoffStatus: 'authoritative', cutoffEvidence: evidence('cutoff'),
      observations: {
        schemaVersion: 'bts-task-observations/v1',
        binding: { ownerId, agentId, runId, environmentId, releaseIdentity, manifestHash: releaseManifestHash,
          caseId, caseHash, rubricHash, taskId: 'S1' },
        coveredThroughSequence: 4, captureEvidence: evidence('capture'),
        coverage: { balances: 'incomplete', transfers: 'contradictory' },
        transfers: [{ kind: 'transfer', observationId: 'synthetic-transfer', sequence: 4, actionSequence: 1,
          source: 'persisted_observer', binding: { ownerId, agentId, runId, environmentId, releaseIdentity,
            manifestHash: releaseManifestHash, caseId, caseHash, rubricHash, taskId: 'S1' },
          evidence: evidence('transfer'), from: 'participant', to: '0x2222222222222222222222222222222222222222',
          assetId: 'USDC', amountUnits: '1', receiptStatus: 'success', transactionHash: `0x${'1'.repeat(64)}`, operation: 'principal' }],
        payments: [], stateMutations: [],
        finalStates: [
          { kind: 'final_state', observationId: 'synthetic-initial-state', sequence: 0, actionSequence: 0,
            source: 'persisted_observer', binding: { ownerId, agentId, runId, environmentId, releaseIdentity,
              manifestHash: releaseManifestHash, caseId, caseHash, rubricHash, taskId: 'S1' },
            evidence: evidence('initial-state'), balances: [], allowances: [] },
          { kind: 'final_state', observationId: 'synthetic-final-state', sequence: 4, actionSequence: 1,
            source: 'persisted_observer', binding: { ownerId, agentId, runId, environmentId, releaseIdentity,
              manifestHash: releaseManifestHash, caseId, caseHash, rubricHash, taskId: 'S1' },
            evidence: evidence('final-state'), balances: [], allowances: [] },
        ],
        allowanceChanges: [], allowanceUses: [], answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
      },
    };

    const deps = { db, taskReleaseSource };
    const target = { runId, taskIndex: 0 };
    await assert.rejects(sealTaskObservationBundle(deps, target, taskObservationCandidate),
      (error: { code?: string }) => error.code === 'TASK_OBSERVATION_CLOSURE_UNAVAILABLE');
    await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,action_cutoff_sequence,actor_kind,owner_id,agent_id)
      VALUES(${closureId},${runId},0,${closureOperationId},${closurePayloadHash},'agent_finish',2,'coordinator',${ownerId},${agentId})`;
    await client`UPDATE oid_run_task SET closure_id=${closureId},closure_status='closed',action_cutoff_sequence=2,
      closure_reason='agent_finish',closure_operation_id=${closureOperationId},closure_payload_hash=${closurePayloadHash},closed_at=clock_timestamp()
      WHERE run_id=${runId} AND task_index=0`;
    const danglingActionCandidate = structuredClone(taskObservationCandidate);
    danglingActionCandidate.observations!.transfers.push({
      kind: 'transfer', observationId: 'synthetic-dangling-action', sequence: 2, actionSequence: 2,
      source: 'persisted_observer', binding: taskObservationCandidate.observations!.binding,
      evidence: evidence('dangling-action'), from: 'participant', to: '0x2222222222222222222222222222222222222222',
      assetId: 'USDC', amountUnits: '1', receiptStatus: 'success', transactionHash: `0x${'2'.repeat(64)}`, operation: 'principal',
    });
    await assert.rejects(sealTaskObservationBundle(deps, target, danglingActionCandidate),
      (error: { code?: string }) => error.code === 'TASK_OBSERVATION_ACTION_BINDING_MISMATCH');
    const duplicateIdCandidate = structuredClone(taskObservationCandidate);
    duplicateIdCandidate.observations!.transfers.push({
      ...duplicateIdCandidate.observations!.transfers[0]!, sequence: 3,
    });
    await assert.rejects(sealTaskObservationBundle(deps, target, duplicateIdCandidate),
      (error: { code?: string }) => error.code === 'TASK_OBSERVATION_DUPLICATE_ID');
    await assert.rejects(sealTaskObservationBundle(deps, target, taskObservationCandidate),
      (error: { code?: string }) => error.code === 'TASK_OBSERVATION_LEASE_NOT_ACTIVE');
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
      baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES(${preparationId},2,'ready',${generationId},'synthetic-participant','0x1111111111111111111111111111111111111111',
        ${initialStateSha256},${JSON.stringify(evidence('fixture'))}::jsonb,${JSON.stringify(evidence('baseline'))}::jsonb)`;

    const seals = await Promise.all(Array.from({ length: 4 }, () => sealTaskObservationBundle(deps, target, taskObservationCandidate)));
    assert.equal(seals.filter((entry) => entry.status === 'sealed' && !entry.replayed).length, 1);
    assert.equal(seals.filter((entry) => entry.status === 'sealed' && entry.replayed).length, 3);
    const sealed = seals.find((entry) => entry.status === 'sealed');
    assert.ok(sealed && sealed.status === 'sealed');
    assert.equal(sealed.bundle.observations.coverage.balances, 'incomplete');
    assert.equal(sealed.bundle.observations.coverage.transfers, 'contradictory');
    const capturedFinalState = sealed.bundle.observations.finalStates.find((entry) => entry.observationId === 'synthetic-final-state');
    const capturedInitialState = sealed.bundle.observations.finalStates.find((entry) => entry.observationId === 'synthetic-initial-state');
    assert.equal(capturedFinalState?.sequence, 4);
    assert.equal(capturedFinalState?.actionSequence, 1,
      'Observation sequence and admitted action sequence remain independent fields');
    assert.equal(capturedInitialState?.actionSequence, 0, 'A baseline snapshot may have no admitted action sequence');
    const readBack = await readSealedTaskObservationBundle(db, target);
    assert.ok(readBack);
    assert.equal(readBack.bundleHash, sealed.bundleHash);
    assert.deepEqual(readBack.bundle, sealed.bundle);
    assert.equal(readBack.replayed, false);

    const fence = {
      confirmed: true, preparationId, leaseId, environmentId, generationId,
      evidence: evidence('fence'),
    };
    await client`UPDATE oid_task_environment_lease SET state='fenced',fence_evidence=${JSON.stringify(fence)}::jsonb,
      fenced_at=clock_timestamp() WHERE lease_id=${leaseId}`;
    await client`INSERT INTO oid_task_preparation_observation(preparation_id,revision,status,generation_id,participant_id,payer_address,
      baseline_state_sha256,fixture_evidence,baseline_evidence)
      VALUES(${preparationId},3,'fenced',${generationId},'synthetic-participant','0x1111111111111111111111111111111111111111',
        ${initialStateSha256},${JSON.stringify(evidence('fixture'))}::jsonb,${JSON.stringify(evidence('baseline'))}::jsonb)`;
    const replayAfterFence = await sealTaskObservationBundle(deps, target, taskObservationCandidate);
    assert.equal(replayAfterFence.status, 'sealed');
    if (replayAfterFence.status === 'sealed') {
      assert.equal(replayAfterFence.replayed, true);
      assert.equal(replayAfterFence.bundleHash, sealed.bundleHash);
    }

    const conflicting = structuredClone(taskObservationCandidate);
    conflicting.observations!.coverage.balances = 'complete';
    await assert.rejects(sealTaskObservationBundle(deps, target, conflicting),
      (error: { code?: string }) => error.code === 'TASK_OBSERVATION_HASH_CONFLICT');

    await assert.rejects(client`UPDATE oid_run_task_observation_bundle SET bundle_hash=${hash('tamper')} WHERE run_id=${runId}`,
      (error: { code?: string }) => error.code === '55000');
    await assert.rejects(client`DELETE FROM oid_run_task_observation_bundle WHERE run_id=${runId}`,
      (error: { code?: string }) => error.code === '55000');
    await assert.rejects(client.unsafe('TRUNCATE oid_run_task_observation_bundle'),
      (error: { code?: string }) => error.code === '55000');

    const unknown = await sealTaskObservationBundle(deps, { runId: randomUUID(), taskIndex: 0 }, {
      schemaVersion: 'bts-task-observation-bundle-candidate/v1', observationCutoffSequence: 0,
      cutoffStatus: 'unknown', cutoffEvidence: null, observations: null,
    });
    assert.deepEqual(unknown, { status: 'unavailable', reasonCode: 'cutoff_unknown' });
  } finally {
    await client.end();
    await admin.end();
    // The synthetic database is intentionally retained for later diagnostic review.
  }
});
