import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import { issueBonusGrant } from './ledger.js';
import { acceptLaunchIntent, createLaunchIntent, type RunServiceDependencies } from './run-service.js';
import type { RunAdmissionRelease } from './task-release.js';

const enabled = process.env.OID_RUN_SERVICE_RESTORE_REPLAY_PG_TEST === '1';
const hash = (value: string) => createHash('sha256').update(value).digest('hex');

const release: RunAdmissionRelease = {
  releaseIdentity: 'restore-replay-pg-v1',
  benchmarkVersion: 'restore-replay-pg-v1',
  manifestHash: hash('restore-replay-manifest'),
  benchmarkHash: hash('restore-replay-benchmark'),
  policyHash: hash('restore-replay-policy'),
  mode: 'training',
  taskIds: ['S1', 'M1', 'H1'],
  weights: [1, 2, 3],
  priceUnits: '500000',
  precision: 6,
};

const admissionReleaseProvider = {
  async getActiveAdmissionRelease(mode: 'training' | 'ranked') {
    return mode === 'training' ? release : null;
  },
  async getValidatedRelease() { return null; },
  getPublicCatalog() { return []; },
} satisfies NonNullable<RunServiceDependencies['admissionReleaseProvider']>;

function newOperation(prefix: string) { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }

function errorCode(expected: string) {
  return (error: unknown) => {
    assert.equal(error && typeof error === 'object' && 'code' in error ? error.code : undefined, expected);
    return true;
  };
}

async function ownerEffects(client: ReturnType<typeof postgres>, ownerId: string) {
  const rows = await client`SELECT
      (SELECT count(*)::int FROM oid_run_launch_intent WHERE owner_id=${ownerId}) AS intents,
      (SELECT count(*)::int FROM oid_benchmark_run WHERE owner_id=${ownerId}) AS runs,
      (SELECT count(*)::int FROM oid_run_operation WHERE owner_id=${ownerId}) AS operations,
      (SELECT count(*)::int FROM oid_ledger_audit WHERE subject_owner_id=${ownerId}) AS audits,
      (SELECT count(*)::int FROM oid_run_reservation WHERE owner_id=${ownerId}) AS reservations,
      (SELECT count(*)::int FROM oid_run_budget_hold WHERE owner_id=${ownerId}) AS holds,
      (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=${ownerId}) AS ledger_entries`;
  return rows[0];
}

test('restored run service replays existing intent and acceptance without live admission policy',
  { skip: !enabled, timeout: 60_000 }, async () => {
    const sourceUrlValue = process.env.OID_DATABASE_URL;
    assert.ok(sourceUrlValue, 'The Docker runtime must provide its isolated owner PostgreSQL URL');
    const sourceUrl = new URL(sourceUrlValue);
    assert.equal(sourceUrl.hostname, 'postgres', 'This regression must run inside the owner-identity Docker network');
    assert.equal(sourceUrl.username, 'oid_owner');
    assert.equal(sourceUrl.pathname, '/owner_identity');

    const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
    const targetUrl = new URL(sourceUrlValue);
    targetUrl.pathname = `/${databaseName}`;
    const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
    const client = postgres(targetUrl.toString(), { max: 8, connect_timeout: 10 });
    const db = drizzle(client) as unknown as OwnerDatabase;

    try {
      await admin.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
      const migration = spawnSync(process.execPath,
        ['--import', './packages/owner-identity/node_modules/tsx/dist/loader.mjs', 'packages/owner-identity/src/migrate.ts'],
        { cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: targetUrl.toString() }, encoding: 'utf8', timeout: 45_000 });
      assert.equal(migration.status, 0,
        `The newly created replay acceptance database must migrate: ${migration.stderr || migration.stdout}`);

      const userId = randomUUID();
      const ownerId = randomUUID();
      const agentId = randomUUID();
      await client`INSERT INTO oid_auth_user(id,name,email,email_verified)
        VALUES(${userId},'Restore replay fixture',${`${userId}@example.invalid`},true)`;
      await client`INSERT INTO oid_owner(id,auth_user_id,admission_status)
        VALUES(${ownerId},${userId},'admitted')`;
      await client`INSERT INTO oid_agent(id,owner_id,name)
        VALUES(${agentId},${ownerId},'Restore replay agent')`;
      await client`INSERT INTO oid_agent_policy(agent_id,training,ranked,revision)
        VALUES(${agentId},true,false,1)`;
      await client`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,operation_limit_units,
          utc_day_limit_units,category_limits,revision)
        VALUES(${ownerId},${agentId},false,NULL,NULL,'{"benchmark":null,"forum":null}'::jsonb,1)`;
      await issueBonusGrant(db, { actorOwnerId: ownerId, ownerId,
        operationId: newOperation('restore_grant'), amount: '1.000000', reason: 'Isolated restore replay funding fixture' });
      const agent = await client`SELECT access_generation FROM oid_agent WHERE id=${agentId}`;
      assert.equal(Number(agent[0]?.access_generation), 1);

      const configuredDeps = {
        db,
        betaOperationsEnabled: true,
        bonusOnly: true,
        admissionReleaseProvider,
        intentTtlSeconds: 900,
        maxIntentTtlSeconds: 3600,
        queueWaitSeconds: 3600,
        maxQueueWaitSeconds: 86_400,
        executionCapacity: 1,
        maxPendingIntentsPerOwner: 4,
        maxPendingIntentsGlobal: 20,
        maxAcceptedRunsPerOwner: 4,
        maxAcceptedRunsGlobal: 20,
        successorPreparationPolicyVersion: "local-bef-successor-preparation/v1",
        successorPreparationTimeoutSeconds: 180,
      } satisfies RunServiceDependencies;
      // This models the restored API profile: report/read/replay services are available, while
      // executor coordination is disabled and admission policy/provider wiring is intentionally absent.
      const restoredDeps = { db, betaOperationsEnabled: true } satisfies RunServiceDependencies;
      const policyWithoutProvider = { ...configuredDeps, admissionReleaseProvider: null } satisfies RunServiceDependencies;

      const createInput = {
        ownerId, agentId, mode: 'training' as const, taskIds: ['S1'], cashCeiling: '0',
        expectedReleaseIdentity: release.releaseIdentity, expectedManifestHash: release.manifestHash,
        expectedQuotePrice: '0.083334', operationId: newOperation('restore_create'),
      };
      const beforeInvalid = await ownerEffects(client, ownerId);
      for (const id of ['S2','S3','S4','M2','M3','M4','H2','H3','U1']) {
        for (const taskIds of [[id], ['S1',id]]) {
          await assert.rejects(createLaunchIntent(configuredDeps, {...createInput, taskIds,
            operationId:newOperation('invalid_training')}), errorCode('INVALID_TASK_SELECTION'));
        }
      }
      await assert.rejects(createLaunchIntent(configuredDeps, {...createInput,taskIds:['S1','S1'],
        operationId:newOperation('duplicate_training')}),errorCode('INVALID_TASK_SELECTION'));
      await assert.rejects(createLaunchIntent(configuredDeps, {...createInput,expectedQuotePrice:'0.033334',
        operationId:newOperation('stale_training')}),errorCode('STALE_RUN_INTENT'));
      assert.deepEqual(await ownerEffects(client,ownerId),beforeInvalid,
        'excluded mixed duplicate and stale requests create no intent, run, reservation, budget hold or ledger effect');
      const created = await createLaunchIntent(configuredDeps, createInput);
      assert.equal(created.replayed, false);
      const acceptInput = {
        intentId: created.intent.id, ownerId, agentId, accessGeneration: 1,
        operationId: newOperation('restore_accept'),
      };
      const beforeStaleAcceptance=await ownerEffects(client,ownerId);
      release.priceUnits='600000';
      await assert.rejects(acceptLaunchIntent(configuredDeps,acceptInput),errorCode('STALE_RUN_INTENT'));
      assert.deepEqual(await ownerEffects(client,ownerId),beforeStaleAcceptance,
        'a changed tariff cannot create reservations or holds during acceptance');
      release.priceUnits='500000';
      const accepted = await acceptLaunchIntent(configuredDeps, acceptInput);
      assert.equal(accepted.replayed, false);

      const beforeReplay = await ownerEffects(client, ownerId);
      assert.equal(beforeReplay?.reservations, 1, 'the original run must hold a real bonus-funded reservation');
      assert.equal(beforeReplay?.holds, 1, 'the original run must retain its budget hold');
      assert.equal(beforeReplay?.ledger_entries, 2, 'the owner must have the grant and its run reservation ledger entry');
      const replayedIntent = await createLaunchIntent(restoredDeps, createInput);
      const replayedRun = await acceptLaunchIntent(restoredDeps, acceptInput);
      assert.equal(replayedIntent.replayed, true);
      assert.equal(replayedIntent.intent.id, created.intent.id);
      assert.equal(replayedRun.replayed, true);
      assert.equal(replayedRun.run.id, accepted.run.id);
      assert.deepEqual(await ownerEffects(client, ownerId), beforeReplay,
        'same-operation retries return committed rows without creating further durable or financial effects');

      await assert.rejects(createLaunchIntent(restoredDeps, {
        ...createInput, expectedQuotePrice: '0.000001',
      }), errorCode('IDEMPOTENCY_CONFLICT'), 'a reused owner operation ID remains bound to its original payload');
      assert.deepEqual(await ownerEffects(client, ownerId), beforeReplay,
        'a mismatched owner replay creates no additional intent, audit, run, hold, reservation, or ledger entry');

      await assert.rejects(createLaunchIntent(restoredDeps, {
        ...createInput, operationId: newOperation('restore_fresh_create'),
      }), errorCode('RUN_POLICY_UNCONFIGURED'), 'fresh owner admissions remain closed without pinned policy');
      await assert.rejects(createLaunchIntent(policyWithoutProvider, {
        ...createInput, operationId: newOperation('restore_provider_create'),
      }), errorCode('RELEASE_UNAVAILABLE'), 'fresh owner admissions remain closed without a release provider');
      assert.deepEqual(await ownerEffects(client, ownerId), beforeReplay,
        'fresh create failures without policy/provider leave no durable or financial effects');

      const pending = await createLaunchIntent(configuredDeps, {
        ...createInput, operationId: newOperation('restore_pending_create'),
      });
      const pendingAccept = { ...acceptInput, intentId: pending.intent.id, operationId: newOperation('restore_fresh_accept') };
      const beforeFreshAccept = await ownerEffects(client, ownerId);
      await assert.rejects(acceptLaunchIntent(restoredDeps, {
        ...pendingAccept, operationId: acceptInput.operationId,
      }), errorCode('IDEMPOTENCY_CONFLICT'), 'a reused agent operation ID remains bound to the original intent');
      await assert.rejects(acceptLaunchIntent(restoredDeps, pendingAccept), errorCode('RUN_POLICY_UNCONFIGURED'),
        'fresh agent acceptance remains closed without pinned queue policy');
      await assert.rejects(acceptLaunchIntent(policyWithoutProvider, pendingAccept), errorCode('RELEASE_UNAVAILABLE'),
        'fresh agent acceptance remains closed without a release provider');
      assert.deepEqual(await ownerEffects(client, ownerId), beforeFreshAccept,
        'fresh accept failures do not create a run, reservation, hold, audit, or ledger entry');
      const pendingState = await client`SELECT status,run_id FROM oid_run_launch_intent WHERE id=${pending.intent.id}`;
      assert.deepEqual(pendingState[0], { status: 'pending', run_id: null },
        'a rejected fresh acceptance leaves its launch intent pending');

      const fullIntent=await createLaunchIntent(configuredDeps,{...createInput,
        taskIds:['H1','M1','S1'],expectedQuotePrice:'0.500000',operationId:newOperation('full_training')});
      assert.deepEqual(fullIntent.intent.taskIds,['S1','M1','H1']);
      const fullRun=await acceptLaunchIntent(configuredDeps,{...acceptInput,intentId:fullIntent.intent.id,operationId:newOperation('full_accept')});
      assert.deepEqual(fullRun.run.taskIds,['S1','M1','H1']);
      assert.equal(fullRun.run.quotePrice,'0.500000');
      await client`UPDATE oid_agent SET access_revoked_at=clock_timestamp() WHERE id=${agentId}`;
      const beforeRevokedRetry = await ownerEffects(client, ownerId);
      await assert.rejects(acceptLaunchIntent(restoredDeps, acceptInput), errorCode('AGENT_ACCESS_REVOKED'),
        'a cached accepted operation does not bypass agent revocation after restore');
      assert.deepEqual(await ownerEffects(client, ownerId), beforeRevokedRetry,
        'revoked-agent replay denial has no new durable or financial effects');
    } finally {
      await client.end();
      await admin.end();
    }
  });
