import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import { lockBetaRunStartControl, updateBetaOperationsControl } from './beta-operations-control.js';
import { acceptLaunchIntent, claimNextQueuedRun, createLaunchIntent, startQueuedRun,
  type RunServiceDependencies } from './run-service.js';
import type { RunAdmissionRelease, ValidatedTaskRelease } from './task-release.js';

const enabled = process.env.OID_BETA_OPERATIONS_LOCK_ORDER_PG_TEST === '1';
const OPEN_TRAINING_TASKS = ['S1', 'M1', 'H1'] as const;
const RELEASE = {
  releaseIdentity: 'operations-lock-order-pg-test-v1',
  benchmarkVersion: 'operations-lock-order-pg-test-v1',
  manifestHash: createHash('sha256').update('operations-lock-order-manifest').digest('hex'),
  benchmarkHash: createHash('sha256').update('operations-lock-order-benchmark').digest('hex'),
  policyHash: createHash('sha256').update('operations-lock-order-policy').digest('hex'),
};
const ADMISSION_RELEASE: RunAdmissionRelease = {
  ...RELEASE, mode: 'training', taskIds: OPEN_TRAINING_TASKS,
  weights: [1, 2, 3], priceUnits: '6000', precision: 6,
};
const VALIDATED_RELEASE: ValidatedTaskRelease = {
  ...RELEASE, mode: 'training', taskIds: OPEN_TRAINING_TASKS,
  weights: [1, 2, 3],
  taskDeadlines: OPEN_TRAINING_TASKS.map((taskId) => ({ taskId, timeoutSeconds: 120 })),
  overallTimeoutSeconds: 1800, pricing: { priceUnits: '6000', precision: 6 },
};

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function codeOf(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
    ? error.code : undefined;
}

function tracked<T>(promise: Promise<T>) {
  return promise.then((value) => ({ status: 'fulfilled' as const, value }),
    (error: unknown) => ({ status: 'rejected' as const, error, code: codeOf(error) }));
}

async function waitForBlockedQuery(client: ReturnType<typeof postgres>, fragment: string, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = await client`SELECT pid,query,pg_blocking_pids(pid)::int[] AS blockers
      FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
        AND query ILIKE ${`%${fragment}%`} AND cardinality(pg_blocking_pids(pid))>0
      ORDER BY pid LIMIT 1` as unknown as Array<{ pid: number; query: string; blockers: number[] }>;
    if (found[0]) return found[0];
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`postgres_lock_wait_not_observed:${fragment}`);
}

async function waitForBlockedQueryOrSettled(client: ReturnType<typeof postgres>, fragment: string,
  isSettled: () => boolean, timeoutMs = 8000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (isSettled()) return false;
    const found = await client`SELECT pid,query,pg_blocking_pids(pid)::int[] AS blockers
      FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
        AND query ILIKE ${`%${fragment}%`} AND cardinality(pg_blocking_pids(pid))>0
      ORDER BY pid LIMIT 1` as unknown as Array<{ pid: number; query: string; blockers: number[] }>;
    if (found[0]) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`postgres_lock_wait_or_completion_not_observed:${fragment}`);
}

type RunFixture = { ownerId: string; agentId: string; runId: string; intentId: string; claimId: string; queueDeadline: string };

async function insertRunFixture(client: ReturnType<typeof postgres>, name: string, status: 'queued' | 'preparing', withClaim: boolean): Promise<RunFixture> {
  const userId = randomUUID(), ownerId = randomUUID(), agentId = randomUUID(), intentId = randomUUID();
  const runId = randomUUID(), claimId = randomUUID();
  await client`INSERT INTO oid_auth_user(id,name,email,email_verified)
    VALUES(${userId},${`Operations lock fixture ${name}`},${`${userId}@example.invalid`},true)`;
  await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${ownerId},${userId},'admitted')`;
  await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agentId},${ownerId},${`Operations lock agent ${name}`})`;
  await client`INSERT INTO oid_agent_policy(agent_id,training,ranked,revision) VALUES(${agentId},true,false,1)`;
  await client`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
      benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,
      agent_policy_revision,status,created_at,expires_at,accepted_at)
    VALUES(${intentId},${ownerId},${agentId},${`fixture_${randomUUID().replaceAll('-', '')}`},
      ${createHash('sha256').update(`${runId}:intent`).digest('hex')},'training',ARRAY['S1'],${RELEASE.releaseIdentity},
      ${RELEASE.benchmarkVersion},${RELEASE.manifestHash},${RELEASE.benchmarkHash},${RELEASE.policyHash},1000,0,0,1,
      'accepted',clock_timestamp(),clock_timestamp()+interval '2 hours',clock_timestamp())`;
  await client`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
      manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,
      status,queued_at,queue_deadline)
    VALUES(${runId},${intentId},${ownerId},${agentId},'training',ARRAY['S1'],${RELEASE.releaseIdentity},
      ${RELEASE.benchmarkVersion},${RELEASE.manifestHash},${RELEASE.benchmarkHash},${RELEASE.policyHash},1000,0,1,1,
      ${status},clock_timestamp(),clock_timestamp()+interval '1 hour')`;
  await client`UPDATE oid_run_launch_intent SET run_id=${runId} WHERE id=${intentId}`;
  await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES(${runId},0,'S1','queued')`;
  if (withClaim) {
    await client`INSERT INTO oid_run_dispatch_claim(run_id,owner_id,agent_id,claim_id,turn_number,status,claimed_at)
      VALUES(${runId},${ownerId},${agentId},${claimId},1,'claimed',clock_timestamp())`;
    await client`INSERT INTO oid_run_execution_slot(agent_id,owner_id,run_id,claim_id,state,acquired_at)
      VALUES(${agentId},${ownerId},${runId},${claimId},'preparing',clock_timestamp())`;
  }
  const deadline = await client`SELECT queue_deadline FROM oid_benchmark_run WHERE id=${runId}`;
  return { ownerId, agentId, runId, intentId, claimId,
    queueDeadline: new Date(deadline[0]!.queue_deadline).toISOString() };
}

const releaseProvider = {
  async getActiveAdmissionRelease() { return ADMISSION_RELEASE; },
  async getValidatedRelease(releaseIdentity: string, manifestHash: string) {
    return releaseIdentity === RELEASE.releaseIdentity && manifestHash === RELEASE.manifestHash ? VALIDATED_RELEASE : null;
  },
  getPublicCatalog() { return []; },
};

function serviceDependencies(db: OwnerDatabase, provider = releaseProvider): RunServiceDependencies {
  return {
    db, betaOperationsEnabled: true, executionCapacity: 2,
    admissionReleaseProvider: provider,
    intentTtlSeconds: 900, maxIntentTtlSeconds: 3600,
    queueWaitSeconds: 3600, maxQueueWaitSeconds: 86400,
    maxPendingIntentsPerOwner: 4, maxPendingIntentsGlobal: 20,
    maxAcceptedRunsPerOwner: 4, maxAcceptedRunsGlobal: 20,
  };
}

function newOperation(prefix: string) { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }

test('Beta pause serializes against claim/start and create/accept without deadlock or post-pause writes',
  { skip: !enabled, timeout: 60_000 }, async () => {
    const sourceValue = process.env.OID_DATABASE_URL;
    assert.ok(sourceValue, 'The Docker runtime must provide its isolated owner database URL');
    const sourceUrl = new URL(sourceValue);
    assert.equal(sourceUrl.hostname, 'postgres', 'This regression must use the owner-identity Docker network');
    assert.equal(sourceUrl.username, 'oid_owner');
    assert.equal(sourceUrl.pathname, '/owner_identity');
    const observerValue = process.env.OID_OBSERVER_DATABASE_URL;
    assert.ok(observerValue, 'The Docker runtime must provide its independent read-only observer URL');
    const observerUrl = new URL(observerValue);
    assert.equal(observerUrl.hostname, 'postgres');
    assert.equal(observerUrl.username, 'oid_observer');
    assert.equal(observerUrl.pathname, '/owner_identity');

    const databaseName = `oid_acceptance_${randomUUID().replaceAll('-', '')}`;
    const targetUrl = new URL(sourceUrl);
    targetUrl.pathname = `/${databaseName}`;
    const targetObserverUrl = new URL(observerUrl);
    targetObserverUrl.pathname = `/${databaseName}`;
    const admin = postgres(sourceValue, { max: 1, connect_timeout: 10 });
    const client = postgres(targetUrl.toString(), { max: 12, connect_timeout: 10 });
    const db = drizzle(client) as unknown as OwnerDatabase;
    const observer = postgres(targetObserverUrl.toString(), { max: 1, connect_timeout: 10 });
    let releaseFirstReader: () => void = () => {};
    let releaseCreateProvider: () => void = () => {};
    let releaseSecondReader: () => void = () => {};
    try {
      await admin.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
      await admin.unsafe(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
      await client`GRANT USAGE ON SCHEMA public TO oid_observer`;
      await client.unsafe('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
      const migration = spawnSync(process.execPath,
        ['--import', './packages/owner-identity/node_modules/tsx/dist/loader.mjs', 'packages/owner-identity/src/migrate.ts'],
        { cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: targetUrl.toString() }, encoding: 'utf8' });
      assert.equal(migration.status, 0, `The new isolated operations-lock database must migrate: ${migration.stderr}`);

      const startFixture = await insertRunFixture(client, 'start', 'preparing', true);
      const claimFixture = await insertRunFixture(client, 'claim', 'queued', false);
      const deps = serviceDependencies(db);

      // Reproduce the three-way cycle: claim waits for an owner held by an in-flight start;
      // pause queues for control SHARE; that owner then requests SHARE behind the pause writer.
      // With owner-before-control claim ordering, the pause completes before claim reaches SHARE.
      const ownerLocked = deferred();
      const ownerControlGate = deferred();
      releaseFirstReader = () => ownerControlGate.resolve();
      const ownerHolder = tracked(db.transaction(async (tx) => {
        await tx.execute(sql`SELECT id FROM oid_owner WHERE id=${claimFixture.ownerId} FOR NO KEY UPDATE`);
        ownerLocked.resolve();
        await ownerControlGate.promise;
        try { return await lockBetaRunStartControl(tx); }
        catch (error) { return codeOf(error) ?? 'UNKNOWN_DATABASE_ERROR'; }
      }));
      await ownerLocked.promise;
      const claim = tracked(claimNextQueuedRun(deps, { claimId: randomUUID(), maxCandidates: 10 }));
      const claimOwnerWait = await waitForBlockedQuery(client, 'FROM oid_owner');
      assert.ok(claimOwnerWait.blockers.length > 0, 'claim must wait on the owner before the pause race proceeds');
      let pauseClaimSettled = false;
      const pauseForClaim = tracked(updateBetaOperationsControl(db, { actorOwnerId: claimFixture.ownerId,
        operationId: newOperation('pauseclaim'), expectedRevision: 0, mode: 'paused', reasonCode: 'resource_pressure' }))
        .then((result) => { pauseClaimSettled = true; return result; });
      await waitForBlockedQueryOrSettled(client, 'FOR UPDATE', () => pauseClaimSettled);
      releaseFirstReader();
      const [ownerHolderResult, pauseClaimResult, claimResult] = await Promise.all([ownerHolder, pauseForClaim, claim]);
      assert.equal(ownerHolderResult.status, 'fulfilled');
      if (ownerHolderResult.status === 'fulfilled') assert.equal(ownerHolderResult.value, 'BETA_STARTS_PAUSED');
      assert.equal(pauseClaimResult.status, 'fulfilled');
      if (pauseClaimResult.status === 'fulfilled') assert.equal(pauseClaimResult.value.control.mode, 'paused');
      assert.equal(claimResult.status, 'rejected');
      if (claimResult.status === 'rejected') assert.equal(claimResult.code, 'BETA_STARTS_PAUSED');

      const startBefore = await client`SELECT status,started_at,queue_deadline,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=${startFixture.runId} AND event_type='run.started') AS start_events,
          (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=${startFixture.ownerId}) AS ledger_entries,
          (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=${startFixture.runId}) AS reservations,
          (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=${startFixture.runId}) AS budget_holds,
          (SELECT count(*)::int FROM oid_run_operation WHERE owner_id=${startFixture.ownerId} AND action='run_start') AS start_receipts
        FROM oid_benchmark_run WHERE id=${startFixture.runId}`;
      const startDeps: RunServiceDependencies = {
        ...deps,
        admissionReleaseProvider: releaseProvider,
        executionReadinessProvider: { async isPreparedForRelease() {
          return { ready: true, environmentId: 'ops-env-a', evidenceHash: 'a'.repeat(64) };
        } },
      };
      await assert.rejects(startQueuedRun(startDeps, { runId: startFixture.runId, claimId: startFixture.claimId,
        operationId: newOperation('startpause') }), (error: unknown) => codeOf(error) === 'BETA_STARTS_PAUSED');
      const startAfter = await client`SELECT status,started_at,queue_deadline,
          (SELECT count(*)::int FROM oid_run_event WHERE run_id=${startFixture.runId} AND event_type='run.started') AS start_events,
          (SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=${startFixture.ownerId}) AS ledger_entries,
          (SELECT count(*)::int FROM oid_run_reservation WHERE run_id=${startFixture.runId}) AS reservations,
          (SELECT count(*)::int FROM oid_run_budget_hold WHERE run_id=${startFixture.runId}) AS budget_holds,
          (SELECT count(*)::int FROM oid_run_operation WHERE owner_id=${startFixture.ownerId} AND action='run_start') AS start_receipts
        FROM oid_benchmark_run WHERE id=${startFixture.runId}`;
      assert.deepEqual(startAfter[0], startBefore[0], 'paused start must not change run state, queue deadline, holds, ledger or receipt');
      const claimState = await client`SELECT r.status,r.queue_deadline,
          (SELECT count(*)::int FROM oid_run_dispatch_claim WHERE run_id=r.id) AS claims,
          (SELECT count(*)::int FROM oid_run_execution_slot WHERE run_id=r.id) AS slots
        FROM oid_benchmark_run r WHERE r.id=${claimFixture.runId}`;
      assert.equal(claimState[0]?.status, 'queued');
      assert.equal(new Date(claimState[0]!.queue_deadline).toISOString(), claimFixture.queueDeadline);
      assert.equal(claimState[0]?.claims, 0);
      assert.equal(claimState[0]?.slots, 0);

      const resumed = await updateBetaOperationsControl(db, { actorOwnerId: claimFixture.ownerId,
        operationId: newOperation('resumeclaim'), expectedRevision: 1, mode: 'active', reasonCode: 'maintenance' });
      assert.equal(resumed.control.mode, 'active');

      await client`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,operation_limit_units,
          utc_day_limit_units,category_limits,revision)
        VALUES(${claimFixture.ownerId},${claimFixture.agentId},false,NULL,NULL,'{"benchmark":null,"forum":null}'::jsonb,1)`;
      // Create holds advisory-21 before its gated provider call. Accept must wait for that
      // advisory lock before taking control SHARE; the pending pause writer must then win.
      const pendingIntent = await createLaunchIntent(deps, {
        ownerId: claimFixture.ownerId, agentId: claimFixture.agentId, mode: 'training', taskIds: ['S1'],
        cashCeiling: '0', expectedReleaseIdentity: RELEASE.releaseIdentity, expectedManifestHash: RELEASE.manifestHash,
        expectedQuotePrice: '0.001000', operationId: newOperation('pendingaccept'),
      });
      const bonusGrantId = randomUUID();
      await client`INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id,created_at)
        VALUES(${bonusGrantId},${claimFixture.ownerId},1000,${claimFixture.ownerId},'synthetic operations-lock fixture',
          ${newOperation('fixturegrant')},clock_timestamp())`;
      await client`INSERT INTO oid_ledger_entry(id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,
          amount_units,available_delta_units,reserved_delta_units,expired_delta_units,reason)
        VALUES(${randomUUID()},${claimFixture.ownerId},${claimFixture.ownerId},${bonusGrantId},${newOperation('fixturegrantentry')},
          'bonus_grant','tester_bonus',1000,1000,0,0,'synthetic operations-lock fixture')`;
      const providerReached = deferred();
      const providerGate = deferred();
      const createOperationId = newOperation('createpause');
      releaseCreateProvider = () => providerGate.resolve();
      const gatedProvider = {
        ...releaseProvider,
        async getActiveAdmissionRelease() {
          providerReached.resolve();
          await providerGate.promise;
          return ADMISSION_RELEASE;
        },
      };
      let createSettled = false;
      const create = tracked(createLaunchIntent(serviceDependencies(db, gatedProvider), {
        ownerId: startFixture.ownerId, agentId: startFixture.agentId, mode: 'training', taskIds: ['S1'],
        cashCeiling: '0', expectedReleaseIdentity: RELEASE.releaseIdentity, expectedManifestHash: RELEASE.manifestHash,
        expectedQuotePrice: '0.001000', operationId: createOperationId,
      })).then((result) => { createSettled = true; return result; });
      await providerReached.promise;

      const acceptOperationId = newOperation('acceptpause');
      let acceptSettled = false;
      const accept = tracked(acceptLaunchIntent(deps, { intentId: pendingIntent.intent.id,
        ownerId: claimFixture.ownerId, agentId: claimFixture.agentId, accessGeneration: 1,
        operationId: acceptOperationId })).then((result) => { acceptSettled = true; return result; });
      await waitForBlockedQuery(client, 'pg_advisory_xact_lock');

      const secondReaderReady = deferred();
      const secondReaderGate = deferred();
      let secondReaderPid = 0;
      releaseSecondReader = () => secondReaderGate.resolve();
      const secondReader = tracked(db.transaction(async (tx) => {
        const pidRows = await tx.execute(sql`SELECT pg_backend_pid()::int AS pid`) as unknown as Array<{ pid: number }>;
        secondReaderPid = pidRows[0]?.pid ?? 0;
        assert.equal(await lockBetaRunStartControl(tx), 'active');
        secondReaderReady.resolve();
        await secondReaderGate.promise;
      }));
      await secondReaderReady.promise;
      const pauseForCreateAccept = tracked(updateBetaOperationsControl(db, { actorOwnerId: claimFixture.ownerId,
        operationId: newOperation('pauseaccept'), expectedRevision: 2, mode: 'paused', reasonCode: 'incident_response' }));
      const queuedPause = await waitForBlockedQuery(client, 'oid_beta_operations_control WHERE id=1 FOR UPDATE');
      assert.ok(secondReaderPid > 0 && queuedPause.blockers.includes(secondReaderPid),
        'the exclusive control writer must be queued behind the known second-reader transaction');
      const pendingLockEvidence = await client`SELECT a.pid,a.query,a.wait_event_type,pg_blocking_pids(a.pid)::int[] AS blockers,
          l.locktype,l.mode,l.granted,l.relation::regclass::text AS relation,l.transactionid::text AS transactionid
        FROM pg_locks l JOIN pg_stat_activity a USING(pid)
        WHERE a.pid=${queuedPause.pid} OR a.pid=${secondReaderPid}
        ORDER BY a.pid,l.granted,l.locktype,l.mode`;
      releaseCreateProvider();
      const createWait = await waitForBlockedQueryOrSettled(client, 'FOR SHARE', () => createSettled);
      let acceptWait = false;
      if (!createWait) {
        const outcome = await create;
        assert.equal(outcome.status, 'fulfilled', `create acquired its shared control check before pause: ${JSON.stringify({
          status: outcome.status, code: outcome.status === 'rejected' ? outcome.code : undefined, pendingLockEvidence })}`);
        acceptWait = await waitForBlockedQueryOrSettled(client, 'FOR SHARE', () => acceptSettled);
      }
      releaseSecondReader();
      const [readerTwoResult, pauseCreateAcceptResult, createResult, acceptResult] = await Promise.all([
        secondReader, pauseForCreateAccept, create, accept,
      ]);
      assert.equal(readerTwoResult.status, 'fulfilled');
      assert.equal(pauseCreateAcceptResult.status, 'fulfilled');
      if (pauseCreateAcceptResult.status === 'fulfilled') assert.equal(pauseCreateAcceptResult.value.control.mode, 'paused');
      if (createWait) {
        assert.equal(createResult.status, 'rejected');
        if (createResult.status === 'rejected') assert.equal(createResult.code, 'BETA_STARTS_PAUSED');
      } else {
        assert.equal(createResult.status, 'fulfilled', 'create linearized before the durable pause update');
      }
      if (createWait || acceptWait) {
        assert.equal(acceptResult.status, 'rejected');
        if (acceptResult.status === 'rejected') assert.equal(acceptResult.code, 'BETA_STARTS_PAUSED');
      } else {
        assert.equal(acceptResult.status, 'fulfilled', `accept linearized before the durable pause update: ${JSON.stringify({
          status: acceptResult.status, code: acceptResult.status === 'rejected' ? acceptResult.code : undefined })}`);
      }

      const rows = await observer.begin(async (tx) => {
        await tx`SET TRANSACTION READ ONLY`;
        const role = await tx`SELECT current_user AS role,current_setting('transaction_read_only') AS read_only,
            has_table_privilege(current_user,'oid_beta_operations_control','SELECT') AS can_read_control,
            has_table_privilege(current_user,'oid_beta_operations_control','UPDATE') AS can_update_control`;
        const control = await tx`SELECT mode,revision::text,changed_at FROM oid_beta_operations_control WHERE id=1`;
        const events = await tx`SELECT count(*)::int AS count FROM oid_beta_operations_control_event`;
        const queued = await tx`SELECT r.status,r.queue_deadline,i.status AS intent_status,i.run_id,
            (SELECT count(*)::int FROM oid_run_dispatch_claim c WHERE c.run_id=r.id) AS claims,
            (SELECT count(*)::int FROM oid_run_execution_slot s WHERE s.run_id=r.id) AS slots,
            (SELECT count(*)::int FROM oid_run_reservation rr WHERE rr.run_id=r.id) AS reservations
          FROM oid_benchmark_run r JOIN oid_run_launch_intent i ON i.id=r.intent_id WHERE r.id=${claimFixture.runId}`;
        const createEffects = await tx`SELECT
            (SELECT count(*)::int FROM oid_run_launch_intent WHERE owner_id=${startFixture.ownerId} AND operation_id=${createOperationId}) AS intents,
            (SELECT min(created_at) FROM oid_run_launch_intent WHERE owner_id=${startFixture.ownerId} AND operation_id=${createOperationId}) AS created_at,
            (SELECT count(*)::int FROM oid_run_operation WHERE owner_id=${startFixture.ownerId} AND operation_id=${createOperationId}) AS operations`;
        const acceptIntent = await tx`SELECT status,run_id FROM oid_run_launch_intent WHERE id=${pendingIntent.intent.id}`;
        const acceptEffects = await tx`SELECT
            (SELECT count(*)::int FROM oid_run_operation WHERE owner_id=${claimFixture.ownerId} AND operation_id=${acceptOperationId}) AS operations,
            (SELECT queued_at FROM oid_benchmark_run WHERE id=${acceptIntent[0]?.run_id}) AS queued_at`;
        return { role: role[0], control: control[0], events: events[0], queued: queued[0], createEffects: createEffects[0],
          acceptIntent: acceptIntent[0], acceptEffects: acceptEffects[0] };
      });
      assert.deepEqual(rows.role, { role: 'oid_observer', read_only: 'on', can_read_control: true, can_update_control: false });
      assert.equal(rows.control?.mode, 'paused');
      assert.equal(rows.control?.revision, '3');
      assert.equal(rows.events?.count, 3);
      assert.equal(rows.queued?.status, 'queued');
      assert.equal(new Date(rows.queued!.queue_deadline).toISOString(), claimFixture.queueDeadline);
      assert.equal(rows.queued?.intent_status, 'accepted');
      assert.equal(rows.queued?.claims, 0);
      assert.equal(rows.queued?.slots, 0);
      assert.equal(rows.queued?.reservations, 0);
      assert.equal(rows.createEffects?.intents, createWait ? 0 : 1);
      assert.equal(rows.createEffects?.operations, createWait ? 0 : 1);
      if (!createWait) assert.ok(new Date(rows.createEffects!.created_at).getTime() <= new Date(rows.control!.changed_at).getTime(),
        'a create granted ahead of the queued pause must commit before the durable pause timestamp');
      assert.equal(rows.acceptIntent?.status, acceptResult.status === 'fulfilled' ? 'accepted' : 'pending');
      if (acceptResult.status === 'fulfilled') {
        assert.ok(rows.acceptIntent?.run_id);
        assert.equal(rows.acceptEffects?.operations, 1);
        assert.ok(new Date(rows.acceptEffects!.queued_at).getTime() <= new Date(rows.control!.changed_at).getTime(),
          'an accept granted ahead of the queued pause must commit before the durable pause timestamp');
      } else {
        assert.equal(rows.acceptIntent?.run_id, null);
        assert.equal(rows.acceptEffects?.operations, 0);
      }
    } finally {
      releaseFirstReader();
      releaseCreateProvider();
      releaseSecondReader();
      await Promise.allSettled([client.end({ timeout: 1 }), observer.end({ timeout: 1 }), admin.end({ timeout: 1 })]);
    }
  });
