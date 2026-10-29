import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import type { BefObservationPorts, BefReadOnlyPostgresPort } from './bef-observation-ports.js';
import { createBetaPlatformRecoveryMonitor } from './beta-platform-recovery-monitor.js';
import type { TaskActionEvidenceSink } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import { addFixture } from './task-run-completion.test-fixture.js';
import { sha256CanonicalTaskJson } from './task-release.js';

const enabled = process.env.OID_BETA_PLATFORM_RECOVERY_PG_TEST === '1';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const TX_HASH = '0x' + 'a'.repeat(64);
const RECIPIENT = '0x2222222222222222222222222222222222222222';

interface MonitorFixture {
  actionId: string; runId: string; ownerId: string; agentId: string; environmentId: string;
  generationId: string; participantId: string; operationId: string; ownerOperationId: string;
  payloadHash: string; manifestSha256: string; applicationSourceSha256: string;
  command: Record<string, unknown>; selectedAction: Record<string, unknown>; requestSha256: string;
}

async function insertMonitorAction(client: ReturnType<typeof postgres>, fixture: Awaited<ReturnType<typeof addFixture>>): Promise<MonitorFixture> {
  const actionId = randomUUID();
  const grantId = randomUUID();
  const ownerOperationId = 'owner_action_' + randomUUID().replaceAll('-', '');
  const command = { kind: 'transfer', amountUnits: '1', recipient: RECIPIENT, gasLimit: '21000' };
  const payloadHash = sha256CanonicalTaskJson({ runId: fixture.runId, taskIndex: 0, command });
  const manifest = fixture.record.manifest as { executionIdentity: { environmentManifestSha256: string; x402ServiceSha256: string } };
  const manifestSha256 = manifest.executionIdentity.environmentManifestSha256;
  const applicationSourceSha256 = manifest.executionIdentity.x402ServiceSha256;
  const requestSha256 = sha256(fixture.runId + ':' + actionId + ':bef-request');

  await client.unsafe("UPDATE oid_run_task SET accepted_action_sequence=1 WHERE run_id=$1 AND task_index=0", [fixture.runId]);
  await client.unsafe("UPDATE oid_benchmark_run SET overall_deadline=clock_timestamp()+interval '20 minutes' WHERE id=$1", [fixture.runId]);
  await client.unsafe("UPDATE oid_run_task SET deadline_at=clock_timestamp()+interval '20 minutes' WHERE run_id=$1 AND task_index=0", [fixture.runId]);
  await client.unsafe("INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at) " +
    "VALUES($1,$2,$3,$4,'https://example.invalid/api/agent','agent',1,clock_timestamp()+interval '1 day')",
    [grantId, fixture.ownerId, fixture.agentId, 'grant_' + randomUUID().replaceAll('-', '')]);
  await client.unsafe("INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id," +
    "environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json) " +
    "VALUES($1,$2,0,$3,$4,1,$5,'S1',$6,1,$7,$8,'transfer',$9::jsonb)",
    [actionId, fixture.runId, fixture.ownerId, fixture.agentId, grantId, fixture.environmentId, ownerOperationId,
      payloadHash, JSON.stringify(command)]);
  await client.unsafe("INSERT INTO oid_run_task_action_outbox(action_id,status,delivered_at) VALUES($1,'delivered',clock_timestamp())", [actionId]);
  await client.unsafe("INSERT INTO oid_run_task_action_receipt(action_id) VALUES($1)", [actionId]);
  return {
    actionId, runId: fixture.runId, ownerId: fixture.ownerId, agentId: fixture.agentId,
    environmentId: fixture.environmentId, generationId: fixture.generationId, participantId: 'synthetic-participant',
    operationId: randomUUID(), ownerOperationId, payloadHash, manifestSha256, applicationSourceSha256, command,
    selectedAction: { kind: 'transfer', token: '0x3333333333333333333333333333333333333333',
      amountUnits: '1', recipient: RECIPIENT, gasLimit: '21000' }, requestSha256,
  };
}

function sourceRow(fixture: MonitorFixture, outcome: 'success' | 'unknown'): Record<string, unknown> {
  const settled = outcome === 'success';
  return {
    operation_id: fixture.operationId, env_id: fixture.environmentId, generation_id: fixture.generationId,
    participant_id: fixture.participantId, idempotency_key_sha256: sha256('task-action-' + fixture.actionId),
    request_sha256: fixture.requestSha256, operation_kind: 'transfer',
    status: settled ? 'settled' : 'settlement_unknown', transaction_hash: settled ? TX_HASH : null,
    receipt_status: settled ? 'success' : 'unknown', response_sha256: null, generation_status: 'active',
    generation_manifest_sha256: fixture.manifestSha256, environment_manifest_sha256: fixture.manifestSha256,
    selected_action_kind: 'transfer', selected_action_json: fixture.selectedAction,
    selected_action_event_count: 1, selected_action_event_kind: 'transfer',
    selected_action_event_action: fixture.selectedAction, selected_action_event_request_sha256: fixture.requestSha256,
    selected_action_event_json: { actionKind: 'transfer', selectedAction: fixture.selectedAction,
      requestSha256: fixture.requestSha256 },
    selected_outcome: settled ? 'success' : null, selected_transaction_hash: settled ? TX_HASH : null,
    selected_measurement_json: settled ? {
      receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: fixture.selectedAction,
      before: { blockNumber: '1' }, after: { blockNumber: '2' },
    } : null,
    delivery_content_sha256: null, payment_transaction_hash: null, payment_receipt_status: null,
  };
}

function recoveryPorts(input: {
  environmentId: string; initialSource?: Record<string, unknown> | null;
  initiallyUnavailable?: boolean; writes: Array<{ path: string; sha256: string; packet: unknown }>;
}): { ports: BefObservationPorts; setSource: (source: Record<string, unknown> | null) => void; setUnavailable: (value: boolean) => void } {
  let source = input.initialSource ?? null;
  let unavailable = input.initiallyUnavailable ?? false;
  const port: BefReadOnlyPostgresPort = {
    environmentId: input.environmentId,
    async withRepeatableRead<T>(callback: (read: (statement: string, parameters?: readonly unknown[]) => Promise<unknown>) => Promise<T>): Promise<T> {
      return callback(async (statement) => {
        if (unavailable) {
          const error = new Error('bef_observer_connection_unavailable');
          error.name = 'BefObservationPortError';
          throw error;
        }
        if (statement.includes('SELECT 1 AS ok')) return [{ ok: 1 }];
        return source ? [source] : [];
      });
    },
    async readFenceProof() { return { generation: null, preparation: null }; },
  };
  const evidenceSink: TaskActionEvidenceSink = {
    async write(packet) {
      const path = 'synthetic-platform-recovery/' + String(input.writes.length + 1).padStart(3, '0') + '.json';
      const digest = sha256(JSON.stringify(packet));
      input.writes.push({ path, sha256: digest, packet });
      return { path, sha256: digest };
    },
  };
  return {
    ports: { postgresByEnvironment: { [input.environmentId]: port }, rpcByEnvironment: {},
      evidenceSink: evidenceSink as unknown as BefObservationPorts['evidenceSink'], close: async () => undefined },
    setSource(value) { source = value; },
    setUnavailable(value) { unavailable = value; },
  };
}

async function readMonitorState(observer: ReturnType<typeof postgres>, fixture: MonitorFixture) {
  const found = await observer.begin(async (tx) => {
    await tx.unsafe('SET TRANSACTION READ ONLY');
    return await tx.unsafe("SELECT run.status AS run_status,recovery.status AS recovery_status,recovery.clock_excluded_ms," +
      "EXTRACT(EPOCH FROM (recovery.deadline_at-recovery.started_at))*1000 AS recovery_window_ms," +
      "receipt.receipt_status,receipt.receipt_revision,receipt.transaction_hash,receipt.tool_response_hash," +
      "(SELECT count(*)::int FROM oid_run_task_action WHERE run_id=run.id) AS action_count," +
      "(SELECT count(*)::int FROM oid_run_task_action_reconciliation WHERE action_id=$2) AS reconciliation_count," +
      "(SELECT count(*)::int FROM oid_run_platform_recovery_observation WHERE action_id=$2) AS observation_count," +
      "(SELECT count(*)::int FROM oid_run_platform_refund WHERE run_id=run.id) AS refund_count," +
      "(SELECT count(*)::int FROM oid_ledger_entry WHERE owner_id=run.owner_id) AS owner_ledger_count " +
      "FROM oid_benchmark_run run JOIN oid_run_platform_recovery recovery ON recovery.run_id=run.id " +
      "JOIN oid_run_task_action_receipt receipt ON receipt.action_id=recovery.action_id WHERE run.id=$1 AND recovery.action_id=$2",
      [fixture.runId, fixture.actionId]);
  });
  assert.equal(found.length, 1);
  return found[0]!;
}

test('the monitor resumes after restart and sends expired recovery to fencing before observer I/O', { skip: !enabled }, async () => {
  const sourceUrlValue = process.env.OID_DATABASE_URL;
  assert.ok(sourceUrlValue, 'The pinned Docker runtime must provide its private owner database URL');
  const sourceUrl = new URL(sourceUrlValue);
  assert.equal(sourceUrl.hostname, 'postgres');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const observerUrlValue = process.env.OID_OBSERVER_DATABASE_URL;
  assert.ok(observerUrlValue, 'The pinned Docker runtime must provide its read-only observer URL');
  const observerUrl = new URL(observerUrlValue);
  assert.equal(observerUrl.hostname, 'postgres');
  assert.equal(observerUrl.username, 'oid_observer');
  assert.equal(observerUrl.pathname, '/owner_identity');
  const databaseName = 'oid_acceptance_' + randomUUID().replaceAll('-', '');
  assert.match(databaseName, /^oid_acceptance_[a-f0-9]{32}$/);
  const targetUrl = new URL(sourceUrlValue);
  targetUrl.pathname = '/' + databaseName;
  observerUrl.pathname = '/' + databaseName;
  const admin = postgres(sourceUrlValue, { max: 1, connect_timeout: 10 });
  let client = postgres(targetUrl.toString(), { max: 8, connect_timeout: 10 });
  let observer: ReturnType<typeof postgres> | undefined;
  try {
    await admin.unsafe('CREATE DATABASE ' + databaseName + ' TEMPLATE template0');
    await admin.unsafe('GRANT CONNECT ON DATABASE ' + databaseName + ' TO oid_observer');
    const migration = spawnSync('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], {
      cwd: '/workspace', env: { ...process.env, OID_DATABASE_URL: targetUrl.toString() }, encoding: 'utf8',
    });
    assert.equal(migration.status, 0,
      'The fresh recovery-monitor acceptance database must migrate: ' + (migration.stderr || migration.stdout));
    const grantExistingTables = postgres(targetUrl.toString(), { max: 1, connect_timeout: 10 });
    try {
      await grantExistingTables.unsafe('GRANT USAGE ON SCHEMA public TO oid_observer');
      await grantExistingTables.unsafe('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer');
    } finally { await grantExistingTables.end(); }
    observer = postgres(observerUrl.toString(), { max: 2, connect_timeout: 10 });
    const identities = await Promise.all([
      client.unsafe('SELECT current_database() AS database_name,current_user AS role'),
      observer.begin(async (tx) => {
        await tx.unsafe('SET TRANSACTION READ ONLY');
        return tx.unsafe("SELECT current_database() AS database_name,current_user AS role," +
          "current_setting('transaction_read_only') AS read_only");
      }),
    ]);
    assert.deepEqual(identities[0]?.[0], { database_name: databaseName, role: 'oid_owner' });
    assert.deepEqual(identities[1]?.[0], { database_name: databaseName, role: 'oid_observer', read_only: 'on' });
    const ownerDb = drizzle(client) as unknown as OwnerDatabase;

    const resumedFixture = await addFixture(client, { actionOpen: true, fence: false });
    const resumedAction = await insertMonitorAction(client, resumedFixture);
    const evidenceWrites: Array<{ path: string; sha256: string; packet: unknown }> = [];
    const resumedPorts = recoveryPorts({ environmentId: resumedAction.environmentId, initiallyUnavailable: true, writes: evidenceWrites });
    const firstProcess = createBetaPlatformRecoveryMonitor({ db: ownerDb, observationPorts: resumedPorts.ports,
      actionEvidenceSink: resumedPorts.ports.evidenceSink as TaskActionEvidenceSink });
    const interrupted = await firstProcess.tick();
    assert.ok(interrupted.recoveringRunIds.includes(resumedAction.runId));
    assert.ok(interrupted.unknownActionIds.includes(resumedAction.actionId));
    const afterOutage = await readMonitorState(observer, resumedAction);
    assert.equal(afterOutage.run_status, 'running');
    assert.equal(afterOutage.recovery_status, 'unknown');
    assert.equal(afterOutage.receipt_status, 'unknown');
    assert.equal(Number(afterOutage.reconciliation_count), 1);

    resumedPorts.setUnavailable(false);
    resumedPorts.setSource(sourceRow(resumedAction, 'success'));
    // A fresh monitor instance models coordinator restart. It reads the existing recovery and
    // original operation; it does not create a second admitted action or resubmit a command.
    const restartedProcess = createBetaPlatformRecoveryMonitor({ db: ownerDb, observationPorts: resumedPorts.ports,
      actionEvidenceSink: resumedPorts.ports.evidenceSink as TaskActionEvidenceSink });
    const resumed = await restartedProcess.tick();
    assert.ok(resumed.reconciledActionIds.includes(resumedAction.actionId));
    const afterRestart = await readMonitorState(observer, resumedAction);
    assert.equal(afterRestart.run_status, 'running');
    assert.equal(afterRestart.recovery_status, 'recovered');
    assert.equal(afterRestart.receipt_status, 'observed');
    assert.equal(afterRestart.transaction_hash, TX_HASH);
    assert.ok(afterRestart.tool_response_hash);
    assert.equal(Number(afterRestart.action_count), 1);
    assert.equal(Number(afterRestart.reconciliation_count), 2);
    assert.equal(Number(afterRestart.observation_count), 2);
    assert.equal(Number(afterRestart.refund_count), 0);
    assert.ok(evidenceWrites.length >= 2);
    const recoveredPacket = evidenceWrites[evidenceWrites.length - 1]?.packet as Record<string, unknown> | undefined;
    assert.ok(recoveredPacket && recoveredPacket.reasonCode === 'platform_recovery_original_operation_terminal');
    assert.deepEqual(recoveredPacket?.recoverySource && Object.keys(recoveredPacket.recoverySource as object).sort(),
      ['schema', 'selectedMeasurementSha256', 'sourceResponseSha256', 'sourceSnapshotSha256']);
    assert.equal((recoveredPacket?.recoverySource as Record<string, unknown> | undefined)?.sourceResponseSha256, null);
    assert.equal(Object.hasOwn(recoveredPacket ?? {}, 'httpStatus'), false);
    assert.equal(Object.hasOwn(recoveredPacket ?? {}, 'rawResponseSha256'), false);
    assert.equal(recoveredPacket?.receiptGasUsed, '21000');
    assert.equal(recoveredPacket?.receiptEffectiveGasPriceWei, '7');

    const lateFixture = await addFixture(client, { actionOpen: true, fence: false });
    const lateAction = await insertMonitorAction(client, lateFixture);
    await client.unsafe("WITH clock AS (SELECT clock_timestamp() AS at) " +
      "INSERT INTO oid_run_platform_recovery(action_id,run_id,owner_id,agent_id,task_index,environment_id,operation_id," +
      "payload_hash,incident_evidence_hash,started_at,deadline_at,clock_excluded_ms,status) " +
      "SELECT $1,$2,$3,$4,0,$5,$6,$7,$8,clock.at-interval '181 seconds',clock.at-interval '1 second',0,'recovering' FROM clock",
      [lateAction.actionId, lateAction.runId, lateAction.ownerId, lateAction.agentId, lateAction.environmentId,
        lateAction.ownerOperationId, lateAction.payloadHash, sha256(lateAction.runId + ':late-incident')]);
    const lateWrites: Array<{ path: string; sha256: string; packet: unknown }> = [];
    const latePorts = recoveryPorts({ environmentId: lateAction.environmentId,
      initialSource: sourceRow(lateAction, 'unknown'), writes: lateWrites });
    let lateObserverReads = 0;
    latePorts.ports.postgresByEnvironment[lateAction.environmentId]!.withRepeatableRead = async () => {
      lateObserverReads += 1;
      throw new Error('expired recovery must not wait on an unavailable observer before fencing');
    };
    const lateProcess = createBetaPlatformRecoveryMonitor({ db: ownerDb, observationPorts: latePorts.ports,
      actionEvidenceSink: latePorts.ports.evidenceSink as TaskActionEvidenceSink });
    const late = await lateProcess.tick();
    assert.ok(late.exhaustedRunIds.includes(lateAction.runId));
    assert.equal(late.unknownActionIds.length, 0);
    assert.ok(!late.recoveringRunIds.includes(lateAction.runId));
    assert.equal(lateObserverReads, 0, 'a source outage cannot delay the persisted deadline-to-fence transition');
    const afterLateUnknown = await readMonitorState(observer, lateAction);
    assert.equal(afterLateUnknown.run_status, 'running');
    assert.equal(afterLateUnknown.recovery_status, 'recovering');
    assert.equal(afterLateUnknown.receipt_status, 'pending');
    assert.equal(Number(afterLateUnknown.recovery_window_ms), 180_000);
    assert.equal(Number(afterLateUnknown.clock_excluded_ms), 0);
    assert.equal(Number(afterLateUnknown.refund_count), 0,
      'the cutoff alone cannot invent a source outcome or refund before exact cancellation fencing');
    assert.equal(Number(afterLateUnknown.action_count), 1);
    assert.equal(Number(afterLateUnknown.reconciliation_count), 0);
    assert.equal(lateWrites.length, 0);
  } finally {
    await observer?.end();
    await client.end();
    await admin.end();
  }
});
