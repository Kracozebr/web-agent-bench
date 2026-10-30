import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { OwnerDatabase } from './db.js';
import { addFixture, hash as fixtureHash } from './task-run-completion.test-fixture.js';
import { consumeRunCancellationOutbox, requestRunCancellationFromCoordinator } from './run-service.js';
import { createTaskPreparationCancellationExecutor } from './task-preparation.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import { activeTaskNeedsCancellation, activeTaskNeedsCancellationAfterRecovery, handoffCommittedSuccessor, isResumablePreDispatchPreparation,
  isBoundedSuccessorWindowFailure, isValidSuccessorLocator, leaseGuardedPreparedTaskStartPort,
  predecessorFinishedBeforeOriginalDeadline, successorFailureCancellationReason, parseLocalBefTaskCoordinatorConfig,
  isExpiredKnownRunGap,cancelExpiredKnownRunGaps,isExpiredClosedUngradedTask,cancelExpiredClosedUngradedTasks,
  parseBetaBefTaskCoordinatorConfig,
  BETA_BEF_RUN_SERVICE_POLICY, LOCAL_BEF_RUN_SERVICE_POLICY, PostgresLocalCoordinatorLease, taskIndexFromFenceResult, cleanupFailedLocalBefTaskCoordinatorStartup,
  writeSafeEvidence, type CoordinatorReservedSql } from './bef-task-coordinator.js';
import type { PreparedTaskStartPort, TaskPreparationRecord } from './task-preparation.js';
import { sha256CanonicalTaskJson } from './task-release.js';

const policy = {
  manifestSha256: 'a'.repeat(64),
  scheme: 'exact',
  network: 'eip155:8453',
  asset: `0x${'b'.repeat(40)}`,
  assetTransferMethod: 'eip3009',
  eip712Domain: { name: 'USD Coin', version: '2' },
  maxTimeoutSeconds: 60,
  sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' },
  localAnvil: {
    identity: 'private-anvil-fork', chainId: 8453, anvilVersion: '1.8.6',
    executionNetwork: 'ethereum', hardFork: 'prague', forkBlockNumber: '0x1234', forkBlockHash: `0x${'c'.repeat(64)}`,
  },
  resources: [{ resourceId: 'dataset-a', resourceSha256: 'd'.repeat(64), contentType: 'application/json',
    offers: [{ id: 'canonical', amount: '100000' }] }],
};

test('beta queue policy adds the 24-hour and accepted caps without changing local defaults', () => {
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.queueWaitSeconds, 86400);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.maxQueueWaitSeconds, 86400);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.maxPendingIntentsPerOwner, 2);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.maxPendingIntentsGlobal, 30);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.maxAcceptedRunsPerOwner, 2);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.maxAcceptedRunsGlobal, 8);
  assert.equal(BETA_BEF_RUN_SERVICE_POLICY.executionCapacity, 1);
  assert.equal(LOCAL_BEF_RUN_SERVICE_POLICY.queueWaitSeconds, 900);
  assert.equal(LOCAL_BEF_RUN_SERVICE_POLICY.maxQueueWaitSeconds, 3600);
  assert.equal('maxAcceptedRunsPerOwner' in LOCAL_BEF_RUN_SERVICE_POLICY, false);
});

test('local coordinator config accepts only a pinned private fork and local BEF endpoints', () => {
  const parsed = parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1',
    adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'http://bef-api:18545',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: policy }],
  });
  assert.equal(parsed.environments[0]?.envId, 'bef-env-a');
  assert.equal(parsed.observationPipeline, undefined, 'legacy local config does not enable automatic grading');
  const observationPipeline = { schemaVersion: 'local-bef-training-observation/v1',
    database: { host: 'host.docker.internal', port: 55432, database: 'bef' },
    passwordFile: '/run/secrets/bef_database_observer_password' };
  const observed = parseLocalBefTaskCoordinatorConfig({ ...parsed, observationPipeline });
  assert.equal(observed.observationPipeline?.database.database, 'bef');
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({ ...parsed,
    observationPipeline: { ...observationPipeline, database: { ...observationPipeline.database, host: '8.8.8.8' } } }),
  /local_bef_observer_database_must_be_private/);
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({ ...parsed,
    observationPipeline: { ...observationPipeline, passwordFile: '/tmp/unrelated-secret' } }));
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1', adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'https://external.example',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: policy }],
  }), /local_bef_coordinator_url/);
  assert.throws(() => parseLocalBefTaskCoordinatorConfig({
    schemaVersion: 'local-bef-task-coordinator-config/v1', adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'http://bef-api:18545',
      observerRpcUrl: 'http://anvil-a:8545', x402Policy: { ...policy, network: 'eip155:1' } }],
  }));
});

test('beta coordinator config requires private HTTPS BEF endpoints and private secret references', () => {
  const config = {
    schemaVersion: 'beta-bef-task-coordinator-config/v1',
    adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'https://source-rpc.example',
    observationPipeline: { schemaVersion: 'local-bef-training-observation/v1',
      database: { host: 'bef-observer', port: 55432, database: 'bef' }, passwordFile: 'secrets/bef-observer-password' },
    environments: [{ envId: 'bef-env-a', apiBaseUrl: 'https://bef-api:18545',
      observerRpcUrl: 'https://anvil-a:8545', x402Policy: policy }],
  };
  assert.equal(parseBetaBefTaskCoordinatorConfig(config).environments[0]?.envId, 'bef-env-a');
  assert.throws(() => parseBetaBefTaskCoordinatorConfig({ ...config,
    environments: [{ ...config.environments[0]!, apiBaseUrl: 'http://bef-api:18545' }] }), /beta_bef_coordinator_private_https_required/);
  assert.throws(() => parseBetaBefTaskCoordinatorConfig({ ...config,
    environments: [{ ...config.environments[0]!, apiBaseUrl: 'https://bef.example.com' }] }), /beta_bef_coordinator_private_https_required/);
  assert.throws(() => parseBetaBefTaskCoordinatorConfig({ ...config,
    observationPipeline: { ...config.observationPipeline, database: { ...config.observationPipeline.database, host: '8.8.8.8' } } }),
  /beta_bef_observer_database_must_be_private/);
  assert.throws(() => parseBetaBefTaskCoordinatorConfig({ ...config, adminKeyFile: '../outside-key' }));
});

test('coordinator evidence writes the nested local default and rejects unsafe overrides and symlink escapes', async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'bef-coordinator-evidence-'));
  const projectRoot = join(temporaryRoot, 'project');
  const outsideRoot = join(temporaryRoot, 'outside');
  await Promise.all([mkdir(projectRoot), mkdir(outsideRoot)]);
  try {
    const fixtureId = '10000000-0000-4000-8000-000000000001';
    const fenceId = '10000000-0000-4000-8000-000000000002';
    const fixture = { kind: 'fixture', preparationId: fixtureId, publicPinsSha256: 'a'.repeat(64) };
    const fence = { kind: 'fence', preparationId: fenceId, leaseState: 'fenced' };
    const fixtureRef = await writeSafeEvidence(projectRoot, 'preparation', fixtureId, fixture);
    const fenceRef = await writeSafeEvidence(projectRoot, 'preparation', fenceId, fence);

    assert.match(fixtureRef.path, /^artifacts\/runs\/owner-identity-bef-task-coordinator\/preparation\//);
    assert.match(fenceRef.path, /^artifacts\/runs\/owner-identity-bef-task-coordinator\/preparation\//);
    for (const [reference, expected] of [[fixtureRef, fixture], [fenceRef, fence]] as const) {
      const bytes = await readFile(resolve(projectRoot, reference.path), 'utf8');
      assert.deepEqual(JSON.parse(bytes), expected);
      assert.equal(reference.sha256, createHash('sha256').update(bytes).digest('hex'));
    }

    const betaStyleRef = await writeSafeEvidence(projectRoot, 'preparation', '10000000-0000-4000-8000-000000000003',
      { kind: 'fixture', preparationId: '10000000-0000-4000-8000-000000000003' }, 'runs');
    assert.match(betaStyleRef.path, /^runs\/preparation\//, 'single-component manifest evidence paths remain valid');

    for (const invalidDirectory of ['../escape', '..', '.', 'nested/runs', resolve(temporaryRoot, 'absolute')]) {
      await assert.rejects(writeSafeEvidence(projectRoot, 'preparation', '10000000-0000-4000-8000-000000000004',
        { kind: 'invalid-path' }, invalidDirectory), /local_bef_coordinator_evidence_path_invalid/);
    }

    const escapedRoot = join(projectRoot, 'linked-evidence');
    await symlink(outsideRoot, escapedRoot, 'dir');
    await assert.rejects(writeSafeEvidence(projectRoot, 'preparation', '10000000-0000-4000-8000-000000000005',
      { kind: 'symlink-escape' }, 'linked-evidence'), /local_bef_coordinator_evidence_path_invalid/);
    assert.deepEqual(await readdir(outsideRoot, { recursive: true }), [],
      'evidence-root symlink rejection must leave the outside tree empty');

    const categoryRoot = join(projectRoot, 'category-linked-evidence');
    await mkdir(categoryRoot);
    await symlink(outsideRoot, join(categoryRoot, 'preparation'), 'dir');
    await assert.rejects(writeSafeEvidence(projectRoot, 'preparation', '10000000-0000-4000-8000-000000000006',
      { kind: 'category-symlink-escape' }, 'category-linked-evidence'), /local_bef_coordinator_evidence_path_invalid/);
    assert.deepEqual(await readdir(outsideRoot, { recursive: true }), [],
      'category symlink rejection must leave the outside tree empty');
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test('local coordinator advisory lease binds to one backend and fails closed when its lock proof disappears', async () => {
  let released = 0;
  let ended = 0;
  let held = true;
  const connection: CoordinatorReservedSql = {
    async unsafe(query) {
      if (query.includes('pg_try_advisory_lock')) return [{ acquired: true, backend_pid: 913 }];
      if (query.includes('pg_locks')) return [{ backend_pid: 913, held }];
      return [{ unlocked: true }];
    },
    release() { released += 1; },
  };
  const client = { async reserve() { return connection; }, async end() { ended += 1; } };
  const lease = new PostgresLocalCoordinatorLease(client as never);
  assert.equal(await lease.acquire(), true);
  assert.equal(lease.ownsLease(), true);
  await lease.assertHeld();
  held = false;
  await assert.rejects(lease.assertHeld(), /lease_lost/);
  assert.equal(lease.ownsLease(), false);
  assert.equal(released, 1);
  await lease.stop();
  assert.equal(ended, 1);
});

test('local coordinator does not start when another worker already holds the singleton lock', async () => {
  let released = 0;
  let ended = 0;
  const connection: CoordinatorReservedSql = {
    async unsafe(query) {
      if (query.includes('pg_try_advisory_lock')) return [{ acquired: false, backend_pid: 914 }];
      return [];
    },
    release() { released += 1; },
  };
  const lease = new PostgresLocalCoordinatorLease({ async reserve() { return connection; }, async end() { ended += 1; } } as never);
  assert.equal(await lease.acquire(), false);
  assert.equal(lease.ownsLease(), false);
  assert.equal(released, 1);
  assert.equal(ended, 1);
});

test('failed coordinator startup stops the dedicated lease before closing the shared database client', async () => {
  const order: string[] = [];
  const cleanupError = new Error('lease teardown failed');
  const errors = await cleanupFailedLocalBefTaskCoordinatorStartup({
    async stop() { order.push('coordinator-stop'); throw cleanupError; },
  }, async () => { order.push('database-close'); });
  assert.deepEqual(order, ['coordinator-stop', 'database-close']);
  assert.deepEqual(errors, [cleanupError]);
});

test('successor locator admits only bounded non-final predecessor identities', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const claimId = '20000000-0000-4000-8000-000000000002';
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'training' }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'ranked' }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0, claim_id: claimId, mode: 'evaluation' }), false);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 10, claim_id: claimId }), true);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 11, claim_id: claimId }), false);
  assert.equal(isValidSuccessorLocator({ run_id: runId, predecessor_task_index: 0.5, claim_id: claimId }), false);
  assert.equal(isValidSuccessorLocator({ run_id: 'bad', predecessor_task_index: 0, claim_id: claimId }), false);
});

test('restart recovery resumes only the exact leased never-dispatched preparation', () => {
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'preparing', dispatch_status: null }), true);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'preparing', dispatch_status: 'dispatching' }), false);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'leased', observation_status: 'ready', dispatch_status: 'completed' }), false);
  assert.equal(isResumablePreDispatchPreparation({ lease_state: 'fenced', observation_status: 'preparing', dispatch_status: null }), false);
});

test('only explicit saved successor-policy expiry failures use the no-intent cancellation path', () => {
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_WINDOW_EXPIRED'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_PREPARATION_TIMEOUT'), true);
  assert.equal(isBoundedSuccessorWindowFailure('SUCCESSOR_OVERALL_TIME_EXHAUSTED'), false);
  assert.equal(isBoundedSuccessorWindowFailure('RUN_TASK_PREDECESSOR_NOT_KNOWN'), false);
  assert.equal(isBoundedSuccessorWindowFailure(null), false);
  assert.equal(predecessorFinishedBeforeOriginalDeadline({
    finishedAt: '2026-10-28T00:00:00.000Z', overallDeadline: '2026-10-28T00:05:00.000Z',
  }), true);
  assert.equal(predecessorFinishedBeforeOriginalDeadline({
    finishedAt: '2026-10-28T00:05:00.000Z', overallDeadline: '2026-10-28T00:05:00.000Z',
  }), false);
  assert.equal(predecessorFinishedBeforeOriginalDeadline(null), null);
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_WINDOW_EXPIRED', false, true),
    'coordinator_preparation_failed');
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_POLICY_UNAVAILABLE', false, true),
    'coordinator_preparation_failed');
  assert.equal(successorFailureCancellationReason('SUCCESSOR_PREPARATION_WINDOW_EXPIRED', false, false), null);
  assert.equal(successorFailureCancellationReason('SUCCESSOR_OVERALL_TIME_EXHAUSTED', false, true), null);
  assert.equal(successorFailureCancellationReason('RUN_TASK_PREDECESSOR_NOT_KNOWN', false, true), null);
  assert.equal(successorFailureCancellationReason('RUN_TASK_PREDECESSOR_NOT_KNOWN', true, null),
    'coordinator_interrupted_preparation');
});

const expiredGap={run_id:'10000000-0000-4000-8000-000000000001',claim_id:'10000000-0000-4000-8000-000000000002',
 predecessor_task_index:3,mode:'ranked' as const,run_status:'running',overall_deadline:'2026-10-30T09:12:46.000Z',
 observed_at:'2026-10-30T09:12:46.000Z',predecessor_finished_at:'2026-10-30T09:12:46.000Z',predecessor_status:'completed',
 predecessor_closure_status:'closed',evaluation_status:'known',active_task_count:0,stored_fence_matches:true,terminal_event_matches:true,
 successor_queued:true,claim_slot_matches:true};

const expiredClosedUngradedTask={run_id:'10000000-0000-4000-8000-000000000021',mode:'training',run_status:'running',
 overall_deadline:'2026-10-30T09:12:46.000Z',observed_at:'2026-10-30T09:12:46.000Z',task_status:'active',
 closure_status:'closed',action_cutoff_sequence:'2',accepted_action_sequence:'2',reconciled_action_sequence:'2',active_task_count:1,
 known_evaluation:false,unresolved_cutoff_action:false,active_platform_recovery:false,claim_slot_matches:true};

test('expired closed ungraded cleanup requires a complete resolved cutoff and no known grade or recovery',()=>{
 assert.equal(isExpiredClosedUngradedTask(expiredClosedUngradedTask),true);
 for(const patch of [
  {run_status:'cancelled'},{mode:'pvp'},{observed_at:'2026-10-30T09:12:45.999Z'},
  {task_status:'completed'},{closure_status:'closing'},{action_cutoff_sequence:null},
  {accepted_action_sequence:'1'},{reconciled_action_sequence:'1'},{active_task_count:0},{active_task_count:2},
  {known_evaluation:true},{unresolved_cutoff_action:true},{active_platform_recovery:true},{claim_slot_matches:false},
  {overall_deadline:'invalid'},{observed_at:'invalid'},{action_cutoff_sequence:'-1'},
  {run_id:'not-a-uuid'},
 ])assert.equal(isExpiredClosedUngradedTask({...expiredClosedUngradedTask,...patch}),false);
});

test('expired closed ungraded cleanup requests only normal run cancellation once and skips active recovery',async()=>{
 const calls:string[]=[];let terminal=false;
 const dependencies={db:{execute:async()=>terminal?[]:[expiredClosedUngradedTask,expiredClosedUngradedTask,
   {...expiredClosedUngradedTask,run_id:'10000000-0000-4000-8000-000000000022',active_platform_recovery:true}]},
  async assertLeaseHeld(){calls.push('lease');},
  async requestCancellation(runId:string,reason:string){assert.equal(runId,expiredClosedUngradedTask.run_id);
   assert.equal(reason,'coordinator_run_deadline');calls.push('cancel');terminal=true;},
  async drainCancellations(){calls.push('drain');},
 } as unknown as Parameters<typeof cancelExpiredClosedUngradedTasks>[0];
 assert.equal(await cancelExpiredClosedUngradedTasks(dependencies),1);
 assert.equal(await cancelExpiredClosedUngradedTasks(dependencies),0);
 assert.equal(calls.filter((value)=>value==='cancel').length,1);assert.equal(calls.filter((value)=>value==='drain').length,1);
 const recovering={...dependencies,db:{execute:async()=>[expiredClosedUngradedTask]}} as unknown as Parameters<typeof cancelExpiredClosedUngradedTasks>[0];
 assert.equal(await cancelExpiredClosedUngradedTasks(recovering,new Set([expiredClosedUngradedTask.run_id])),0);
 const lostLease={...dependencies,async assertLeaseHeld(){throw new Error('local_bef_coordinator_lease_lost');}};
 await assert.rejects(()=>cancelExpiredClosedUngradedTasks(lostLease));
 assert.equal(calls.filter((value)=>value==='cancel').length,1);
});

const deadlineCleanupPgEnabled=process.env.OID_COORDINATOR_DEADLINE_CLEANUP_PG_TEST==='1';

async function closeSyntheticDeadlineTaskWithAction(client:ReturnType<typeof postgres>,
 fixture:Awaited<ReturnType<typeof addFixture>>,receiptStatus:'observed'|'pending'|'unknown'):Promise<void>{
 const actionId=randomUUID(),grantId=randomUUID(),closureId=randomUUID();
 const operationId=`deadline_${randomUUID().replaceAll('-','')}`;
 const payloadHash=fixtureHash(`${fixture.runId}:${receiptStatus}:command`),evidenceHash=fixtureHash(`${fixture.runId}:${receiptStatus}:receipt`);
 await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
   VALUES(${grantId},${fixture.ownerId},${fixture.agentId},${`grant_${randomUUID().replaceAll('-','')}`},
     'https://example.invalid/api/agent','agent',1,clock_timestamp()+interval '1 day')`;
 await client`UPDATE oid_run_task SET accepted_action_sequence=1 WHERE run_id=${fixture.runId} AND task_index=0`;
 await client`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,
     environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json)
   VALUES(${actionId},${fixture.runId},0,${fixture.ownerId},${fixture.agentId},1,${grantId},'S1',${fixture.environmentId},
     1,${operationId},${payloadHash},'inspect_catalog','{}'::jsonb)`;
 await client`INSERT INTO oid_run_task_action_outbox(action_id,status,delivered_at)
   VALUES(${actionId},'delivered',clock_timestamp())`;
 if(receiptStatus==='pending')await client`INSERT INTO oid_run_task_action_receipt(action_id) VALUES(${actionId})`;
 else await client`INSERT INTO oid_run_task_action_receipt(action_id,receipt_revision,receipt_status,evidence_hash)
   VALUES(${actionId},1,${receiptStatus},${evidenceHash})`;
 const closureHash=fixtureHash(`${fixture.runId}:${receiptStatus}:closure`);
 await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,operation_id,payload_hash,reason,action_cutoff_sequence,
     actor_kind,owner_id,agent_id)
   VALUES(${closureId},${fixture.runId},0,NULL,${closureHash},'agent_finish',1,'coordinator',${fixture.ownerId},${fixture.agentId})`;
 await client`INSERT INTO oid_run_task_finish_outbox(closure_id,status,delivered_at)
   VALUES(${closureId},'delivered',clock_timestamp())`;
 await client`UPDATE oid_run_task SET closure_id=${closureId},closure_status='closed',closure_payload_hash=${closureHash},
     closure_reason='agent_finish',closed_at=clock_timestamp(),action_cutoff_sequence=1,reconciled_action_sequence=1
   WHERE run_id=${fixture.runId} AND task_index=0`;
}

test('isolated PostgreSQL selector cancels only resolved expired cutoffs through normal cleanup',{skip:!deadlineCleanupPgEnabled},async()=>{
 const sourceUrlValue=process.env.OID_DATABASE_URL;
 assert.ok(sourceUrlValue,'The explicitly enabled isolated coordinator PostgreSQL test must provide OID_DATABASE_URL');
 const sourceUrl=new URL(sourceUrlValue);
 assert.equal(sourceUrl.hostname,'postgres','The isolated coordinator regression must run inside the owner-identity Docker network');
 assert.equal(sourceUrl.username,'oid_owner');assert.equal(sourceUrl.pathname,'/owner_identity');
 const databaseName=`oid_deadline_cleanup_${randomUUID().replaceAll('-','')}`;
 assert.match(databaseName,/^oid_deadline_cleanup_[0-9a-f]{32}$/);
 const testUrl=new URL(sourceUrlValue);testUrl.pathname=`/${databaseName}`;
 const admin=postgres(sourceUrlValue,{max:1,connect_timeout:10});
 let client:ReturnType<typeof postgres>|undefined;
 try{
  await admin.unsafe(`CREATE DATABASE ${databaseName}`);
  const migration=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{
   cwd:'/workspace',env:{...process.env,OID_DATABASE_URL:testUrl.toString()},encoding:'utf8',timeout:60_000});
  assert.equal(migration.status,0,'The deadline cleanup regression database must migrate successfully');
  client=postgres(testUrl.toString(),{max:8,connect_timeout:10});
  const db=drizzle(client) as unknown as OwnerDatabase;
  const good=await addFixture(client,{actionOpen:true,includeEvaluation:false,overallDeadlinePast:true});
  const pending=await addFixture(client,{actionOpen:true,includeEvaluation:false,overallDeadlinePast:true});
  const unknown=await addFixture(client,{actionOpen:true,includeEvaluation:false,overallDeadlinePast:true});
  await closeSyntheticDeadlineTaskWithAction(client,good,'observed');
  await closeSyntheticDeadlineTaskWithAction(client,pending,'pending');
  await closeSyntheticDeadlineTaskWithAction(client,unknown,'unknown');
  const fixtures=[good,pending,unknown];
  const releaseSource={
   async getActiveAdmissionRelease(){return null;},
   async getValidatedReleaseRecord(identity:string,manifestHash:string){
    return fixtures.find((fixture)=>fixture.record.releaseIdentity===identity&&fixture.record.manifestHash===manifestHash)?.record as never??null;
   },
  } satisfies TaskReleaseQuerySource;
  const unbound:Array<{runId:string;taskIndex:number}>=[];
  const cancellationExecutor=createTaskPreparationCancellationExecutor({db,releaseSource,
   environmentSelector:{async selectEnvironment(){throw new Error('deadline cleanup must not select an environment');}},
   preparationAdapter:{async prepare(){throw new Error('stored fence must be reused');},async reconcile(){throw new Error('stored fence must be reused');},
    async fence(){throw new Error('stored fence must be reused');},clearCredentials(){}},
  },{unbindSession(runId,taskIndex){unbound.push({runId,taskIndex});}});
  const cleaned=await cancelExpiredClosedUngradedTasks({db,async assertLeaseHeld(){},
   async requestCancellation(runId,reason){await requestRunCancellationFromCoordinator(db,{runId,reason});},
   async drainCancellations(){await consumeRunCancellationOutbox(db,cancellationExecutor,100);},
  });
  assert.equal(cleaned,1);
  assert.deepEqual(unbound,[{runId:good.runId,taskIndex:0}]);
  for(const [fixture,expectedStatus] of [[good,'cancelled'],[pending,'running'],[unknown,'running']] as const){
   const stateRows:Array<{status:string;claim_status:string;slot_count:number;evaluation_count:number;refund_count:number}>=await client`SELECT r.status,c.status AS claim_status,
       (SELECT count(*)::int FROM oid_run_execution_slot slot WHERE slot.run_id=r.id) AS slot_count,
       (SELECT count(*)::int FROM oid_run_task_evaluation e WHERE e.run_id=r.id) AS evaluation_count,
       (SELECT count(*)::int FROM oid_ledger_entry entry WHERE entry.owner_id=r.owner_id AND entry.entry_type='refund') AS refund_count
     FROM oid_benchmark_run r JOIN oid_run_dispatch_claim c ON c.run_id=r.id WHERE r.id=${fixture.runId}`;
   assert.equal(stateRows[0]?.status,expectedStatus);
   if(fixture===good){
    assert.equal(stateRows[0]?.claim_status,'released');assert.equal(stateRows[0]?.slot_count,0);
    assert.equal(stateRows[0]?.evaluation_count,0);assert.equal(stateRows[0]?.refund_count,0);
   }else{
    assert.equal(stateRows[0]?.claim_status,'claimed');assert.equal(stateRows[0]?.slot_count,1);
    assert.equal(stateRows[0]?.evaluation_count,0);assert.equal(stateRows[0]?.refund_count,0);
   }
  }
 }finally{
  if(client)await client.end();
  await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName}`).catch(()=>undefined);
  await admin.end();
 }
});

test('known task gaps clean up only predecessors that finished at or after the run deadline',()=>{
 assert.equal(isExpiredKnownRunGap({...expiredGap,observed_at:'2026-10-30T09:12:45.999Z'}),false);
 assert.equal(isExpiredKnownRunGap(expiredGap),true);
 assert.equal(isExpiredKnownRunGap({...expiredGap,observed_at:'2026-10-30T09:12:46.001Z'}),true);
 for(const predecessor_finished_at of ['2026-10-30T09:12:46.000Z','2026-10-30T09:12:47.000Z']){
  assert.equal(isExpiredKnownRunGap({...expiredGap,observed_at:'2026-10-30T09:12:48.000Z',predecessor_finished_at}),true);
 }
 assert.equal(isExpiredKnownRunGap({...expiredGap,observed_at:'2026-10-30T09:14:00.000Z',predecessor_finished_at:'2026-10-30T09:12:45.999Z'}),false,
  'a pre-deadline predecessor retains its saved successor-preparation time exclusion after the old wall-clock deadline');
 for(const patch of [{run_status:'cancelled'},{predecessor_status:'active'},{predecessor_closure_status:'open'},{evaluation_status:'unknown'},
  {active_task_count:1},{stored_fence_matches:false},{terminal_event_matches:false},{successor_queued:false},{claim_slot_matches:false},
  {overall_deadline:'invalid'},{observed_at:'invalid'},{predecessor_finished_at:'invalid'},{claim_id:'foreign-nonuuid'},
  {predecessor_finished_at:'2026-10-30T09:12:49.000Z'}])assert.equal(isExpiredKnownRunGap({...expiredGap,...patch}),false);
});

test('deadline gap cleanup uses only normal cancellation/drain once, independently of paused admission or unhealthy runtime',async()=>{
 const calls:string[]=[];let terminal=false;
 const dependencies={db:{execute:async()=>terminal?[]:[expiredGap,expiredGap,{...expiredGap,stored_fence_matches:false}]},
  async assertLeaseHeld(){calls.push('lease');},
  async requestCancellation(runId:string,reason:string){assert.equal(runId,expiredGap.run_id);assert.equal(reason,'coordinator_run_deadline');calls.push('cancel');terminal=true;},
  async drainCancellations(){calls.push('drain');},
 } as unknown as Parameters<typeof cancelExpiredKnownRunGaps>[0];
 assert.equal(await cancelExpiredKnownRunGaps(dependencies),1);
 assert.equal(await cancelExpiredKnownRunGaps(dependencies),0);
 assert.equal(calls.filter((value)=>value==='cancel').length,1);assert.equal(calls.filter((value)=>value==='drain').length,1);
 const lostLease={...dependencies,async assertLeaseHeld(){throw new Error('lease_lost');}};
 await assert.rejects(()=>cancelExpiredKnownRunGaps(lostLease));
 assert.equal(calls.filter((value)=>value==='cancel').length,1);
});

test('lost RAM selection and cancellation cleanup use the exact active task index', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const attached = new Map([[`${runId}:0`, {}], [`${runId}:2`, {}]]);
  assert.equal(activeTaskNeedsCancellation(runId, 2, attached), false);
  assert.equal(activeTaskNeedsCancellation(runId, 1, attached), true);
  assert.equal(activeTaskNeedsCancellation(runId, 12, attached), true);
  assert.equal(taskIndexFromFenceResult({ fenced: true, taskPreparation: {
    taskIndex: 2, preparationId: '30000000-0000-4000-8000-000000000003', generationId: null,
  } }), 2);
  assert.equal(taskIndexFromFenceResult({ fenced: true, taskPreparation: {
    taskIndex: 0, preparationId: '30000000-0000-4000-8000-000000000003', generationId: null,
  } }), 0);
  assert.equal(taskIndexFromFenceResult({ fenced: false }), null);
});

function fencedKnownClosedRecoveryRow(): Record<string, unknown> {
  const runId = '10000000-0000-4000-8000-000000000001';
  const ownerId = '11000000-0000-4000-8000-000000000011';
  const agentId = '12000000-0000-4000-8000-000000000012';
  const closureId = '13000000-0000-4000-8000-000000000013';
  const preparationId = '14000000-0000-4000-8000-000000000014';
  const leaseId = '15000000-0000-4000-8000-000000000015';
  const generationId = '16000000-0000-4000-8000-000000000016';
  const environmentId = 'bef-env-a';
  const releaseIdentity = 'synthetic-release/v1';
  const releaseManifestHash = 'a'.repeat(64);
  const environmentManifestHash = 'b'.repeat(64);
  const applicationSourceHash = 'c'.repeat(64);
  const executionIdentityHash = 'd'.repeat(64);
  const initialStateSha256 = 'e'.repeat(64);
  const caseId = 's1-case';
  const caseHash = 'f'.repeat(64);
  const rubricHash = '1'.repeat(64);
  const closurePayloadHash = '2'.repeat(64);
  const binding = { runId, ownerId, agentId, environmentId, releaseIdentity, manifestHash: releaseManifestHash,
    caseId, caseHash, rubricHash, taskId: 'S1' };
  const closure = { closureId, operationId: 'owner-close-op', payloadHash: closurePayloadHash,
    reason: 'agent_finish', actionCutoffSequence: 0, reconciledActionSequence: 0 };
  const execution = { preparationId, leaseId, generationId, environmentManifestHash, applicationSourceHash,
    executionIdentityHash, initialStateSha256 };
  const observations = { schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 1,
    captureEvidence: { path: 'capture.json', sha256: '3'.repeat(64) } };
  const bundle = { schemaVersion: 'bts-task-observation-bundle/v1', binding, closure, execution,
    cutoff: { observationSequence: 1, status: 'authoritative', evidence: observations.captureEvidence }, observations };
  const result = { status: 'known', taskId: 'S1', outcome: 'passed', mandatoryViolation: null };
  const input = { taskCase: { taskId: 'S1', mode: 'training', caseId, caseHash, rubricHash },
    release: { releaseIdentity, manifestHash: releaseManifestHash },
    run: { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0,
      observationCutoffSequence: 1, cutoffStatus: 'authoritative', cutoffEvidence: observations.captureEvidence }, observations };
  const expectedEvent = { taskIndex: 0, taskId: 'S1', closureId, releaseIdentity, manifestHash: releaseManifestHash,
    inputHash: sha256CanonicalTaskJson(input), resultHash: sha256CanonicalTaskJson(result), evaluatorSourceHash: '4'.repeat(64) };
  return {
    run_id: runId, owner_id: ownerId, agent_id: agentId, run_mode: 'training', run_status: 'running',
    task_index: 0, task_id: 'S1', task_status: 'active', closure_status: 'closed', closure_id: closureId,
    accepted_action_sequence: '0', action_cutoff_sequence: '0', reconciled_action_sequence: '0',
    release_identity: releaseIdentity, release_manifest_hash: releaseManifestHash,
    closure_operation_id: 'owner-close-op', closure_payload_hash: closurePayloadHash, closure_reason: 'agent_finish',
    preparation_id: preparationId, preparation_run_id: runId, preparation_task_index: 0, preparation_task_id: 'S1',
    preparation_release_identity: releaseIdentity, preparation_manifest_hash: releaseManifestHash,
    preparation_case_id: caseId, preparation_case_hash: caseHash, preparation_initial_state_sha256: initialStateSha256,
    preparation_environment_manifest_sha256: environmentManifestHash,
    preparation_application_source_hash: applicationSourceHash, preparation_execution_identity_hash: executionIdentityHash,
    preparation_lease_id: leaseId, preparation_environment_id: environmentId,
    lease_preparation_id: preparationId, lease_id: leaseId, lease_state: 'fenced',
    lease_fence_evidence: { confirmed: true, preparationId, leaseId, environmentId, generationId },
    observation_status: 'fenced', observed_generation_id: generationId, preparation_observation_generation_id: generationId,
    registered_generation_id: generationId, registered_environment_id: environmentId,
    binding_run_id: runId, binding_task_index: 0, binding_environment_id: environmentId, binding_generation_id: generationId,
    binding_manifest_hash: environmentManifestHash, binding_source_hash: applicationSourceHash,
    closure_run_id: runId, closure_task_index: 0, journal_closure_id: closureId, journal_cutoff_sequence: '0',
    journal_payload_hash: closurePayloadHash, journal_reason: 'agent_finish', journal_operation_id: 'owner-close-op',
    journal_owner_id: ownerId, journal_agent_id: agentId,
    bundle_run_id: runId, bundle_task_index: 0, bundle_owner_id: ownerId, bundle_agent_id: agentId, bundle_task_id: 'S1',
    bundle_closure_id: closureId, bundle_preparation_id: preparationId, bundle_lease_id: leaseId,
    bundle_closure_operation_id: 'owner-close-op', bundle_closure_payload_hash: closurePayloadHash,
    bundle_closure_reason: 'agent_finish', bundle_rubric_hash: rubricHash, bundle_initial_state_sha256: initialStateSha256,
    bundle_environment_id: environmentId, bundle_generation_id: generationId,
    bundle_release_identity: releaseIdentity, bundle_release_manifest_hash: releaseManifestHash,
    bundle_case_id: caseId, bundle_case_hash: caseHash,
    bundle_environment_manifest_hash: environmentManifestHash, bundle_application_source_hash: applicationSourceHash,
    bundle_execution_identity_hash: executionIdentityHash, bundle_cutoff_sequence: '0', bundle_reconciled_sequence: '0',
    bundle_hash: sha256CanonicalTaskJson(bundle), bundle_json: bundle,
    evaluation_run_id: runId, evaluation_task_index: 0, evaluation_closure_id: closureId, evaluation_task_id: 'S1',
    evaluation_release_identity: releaseIdentity, evaluation_manifest_hash: releaseManifestHash,
    evaluation_case_hash: caseHash, evaluation_rubric_hash: rubricHash,
    evaluation_input_hash: sha256CanonicalTaskJson(input), evaluation_result_hash: sha256CanonicalTaskJson(result),
    evaluation_evaluator_source_hash: expectedEvent.evaluatorSourceHash, evaluation_input_json: input, evaluation_result_json: result,
    evaluation_event_count: '1', evaluation_event_source: 'coordinator', evaluation_event_payload_hash: sha256CanonicalTaskJson(expectedEvent),
    evaluation_event_payload_json: expectedEvent, terminalization_event_count: '0',
  };
}

test('missing RAM does not cancel an exact fenced, closed, known task awaiting normal terminalization', () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const attached = new Map<string, unknown>();
  const recovery = fencedKnownClosedRecoveryRow();
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, recovery), false);

  // A live open task, or a fenced row for a different generation, does not qualify for this gap.
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, closure_status: 'open', action_cutoff_sequence: null,
  }), true);
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, binding_generation_id: '17000000-0000-4000-8000-000000000017',
  }), true);
  assert.equal(activeTaskNeedsCancellationAfterRecovery(runId, 0, attached, {
    ...recovery, lease_state: 'leased',
  }), true);
});

test('prepared start port checks coordinator lease before and after its delegated work', async () => {
  const order: string[] = [];
  let checks = 0;
  const base = {
    async readCandidatePreparationId() { order.push('read'); return '40000000-0000-4000-8000-000000000004'; },
    async assertReadyInTransaction() { order.push('ready'); return {} as TaskPreparationRecord; },
    hasUsableStartSession() { return true; },
    async attachStartedSession() { order.push('attach'); },
  } as unknown as PreparedTaskStartPort;
  const guarded = leaseGuardedPreparedTaskStartPort(base, async () => { checks += 1; order.push(`lease-${checks}`); });
  const target = { runId: '10000000-0000-4000-8000-000000000001', taskIndex: 1, claimId: '20000000-0000-4000-8000-000000000002' };
  assert.equal(await guarded.readCandidatePreparationId(target), '40000000-0000-4000-8000-000000000004');
  assert.deepEqual(order, ['lease-1', 'read', 'lease-2']);
  order.length = 0;
  await guarded.attachStartedSession({} as TaskPreparationRecord, new Date(Date.now() + 60_000).toISOString());
  assert.deepEqual(order, ['lease-3', 'attach', 'lease-4']);

  let calls = 0;
  order.length = 0;
  const lostAfterRead = leaseGuardedPreparedTaskStartPort(base, async () => {
    calls += 1;
    if (calls === 2) throw new Error('local_bef_coordinator_lease_lost');
  });
  await assert.rejects(lostAfterRead.readCandidatePreparationId(target), /lease_lost/);
  assert.deepEqual(order, ['read']);
});

test('post-commit successor attach failure requests exact task cancellation, while lease loss leaves recovery to the next owner', async () => {
  const runId = '10000000-0000-4000-8000-000000000001';
  const preparation = { intent: { runId, taskIndex: 2 } } as unknown as TaskPreparationRecord;
  const cancellations: Array<{ runId: string; taskIndex: number; reason: string }> = [];
  const failedAttach = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: false, preparation, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() {}, async attach() { throw new Error('session_attach_failed'); },
    async cancelAndFence(cancelRunId, taskIndex, reason) { cancellations.push({ runId: cancelRunId, taskIndex, reason }); },
  });
  assert.equal(failedAttach, 'cancelled');
  assert.deepEqual(cancellations, [{ runId, taskIndex: 2, reason: 'coordinator_executor_session_lost' }]);

  let attached = 0;
  let cancelled = 0;
  const lostLease = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: false, preparation, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() { throw new Error('local_bef_coordinator_lease_lost'); },
    async attach() { attached += 1; }, async cancelAndFence() { cancelled += 1; },
  });
  assert.equal(lostLease, 'lease_lost');
  assert.equal(attached, 0);
  assert.equal(cancelled, 0);

  const replayWithoutRam = await handoffCommittedSuccessor({
    runId, taskIndex: 2, replayed: true, preparation: null, taskDeadline: new Date(Date.now() + 60_000).toISOString(),
    isAttached: () => false, async assertLeaseHeld() {}, async attach() { attached += 1; },
    async cancelAndFence(_runId, taskIndex, reason) { cancellations.push({ runId, taskIndex, reason }); },
  });
  assert.equal(replayWithoutRam, 'cancelled');
  assert.equal(attached, 0);
  assert.equal(cancellations.at(-1)?.taskIndex, 2);
});

test('Postgres advisory lease contends and becomes available after its owning pool closes', {
  skip: process.env.OID_COORDINATOR_LEASE_INTEGRATION !== 'true',
}, async () => {
  const databaseUrl = process.env.OID_DATABASE_URL;
  assert.ok(databaseUrl, 'the explicit owner PostgreSQL integration run must provide OID_DATABASE_URL');
  const first = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  const contender = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  const recovered = new PostgresLocalCoordinatorLease(postgres(databaseUrl, { max: 1, idle_timeout: 0 }));
  try {
    assert.equal(await first.acquire(), true);
    await first.assertHeld();
    assert.equal(await contender.acquire(), false);
    await first.stop();
    assert.equal(await recovered.acquire(), true);
    await recovered.assertHeld();
  } finally {
    await Promise.all([first.stop(), contender.stop(), recovered.stop()]);
  }
});
