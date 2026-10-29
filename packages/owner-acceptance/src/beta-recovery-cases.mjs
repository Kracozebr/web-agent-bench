import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import pg from 'pg';
import { runGenuineS1OwnerCase } from './genuine-s1-cases.mjs';
import { assertSecretFree } from './evidence.mjs';

const { Pool } = pg;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const RECOVERY_WINDOW_MS = 180_000;
const RECOVERY_FIRST_ACTION_KIND = Object.freeze({ S1: 'transfer', S4: 'approve', M3: 'approve' });
const hash = (value) => createHash('sha256').update(value).digest('hex');

function demand(condition, code) { if (!condition) throw Object.assign(new Error(code), { code }); }
function pgRows(value) { if (!Array.isArray(value)) throw new Error('recovery_observer_rows_invalid'); return value; }
function jsonObject(value, code) {
  let parsed = value;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); } catch { demand(false, code); }
  }
  demand(parsed && typeof parsed === 'object' && !Array.isArray(parsed), code);
  return parsed;
}
function canonicalHash(value, canonicalTaskJson) { return hash(canonicalTaskJson(value)); }
function decimalQuantity(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value !== 'string') return null;
  try {
    if (/^0x[0-9a-f]+$/i.test(value)) return BigInt(value).toString(10);
    if (/^(?:0|[1-9][0-9]*)$/.test(value)) return BigInt(value).toString(10);
  } catch { /* return unavailable below */ }
  return null;
}

function recoverySourceBound(source) {
  const operation = source?.result?.[0];
  const execution = source?.selectedExecutions?.[0];
  const proof = source?.recoverySource;
  return source?.result?.length === 1 && source?.selectedExecutions?.length === 1 &&
    proof?.schema === 'bef-recovery-source/v1' && SHA256.test(proof.sourceSnapshotSha256 ?? '') &&
    SHA256.test(proof.selectedMeasurementSha256 ?? '') && proof.sourceResponseSha256 === null &&
    operation?.responseSha256 === null && operation?.idempotencyKeySha256 === source.keySha256 &&
    UUID.test(operation?.operationId ?? '') && SHA256.test(operation?.requestSha256 ?? '') &&
    SHA256.test(operation?.participantIdSha256 ?? '') && operation?.status === 'settled' &&
    operation?.receiptStatus === 'success' && /^0x[0-9a-f]{64}$/.test(operation?.transactionHash ?? '') &&
    operation?.generationStatus === 'fenced' && SHA256.test(execution?.generationManifestSha256 ?? '') &&
    SHA256.test(execution?.environmentManifestSha256 ?? '') &&
    execution?.operationId === operation.operationId && execution?.selectedActionKind === operation.operationKind &&
    SHA256.test(execution?.selectedActionSha256 ?? '') && SHA256.test(execution?.selectedActionEventSha256 ?? '') &&
    execution?.selectedActionEventCount === 1 && execution?.selectedActionEventKind === 'selected_action_bound' &&
    execution?.selectedActionEventActionKind === operation.operationKind &&
    execution?.selectedActionEventRequestSha256 === operation.requestSha256 &&
    execution?.selectedActionEventSelectedActionSha256 === execution?.selectedActionSha256 &&
    execution?.selectedMeasurementSha256 === proof.selectedMeasurementSha256 &&
    execution?.selectedOutcome === operation.receiptStatus &&
    execution?.selectedTransactionHash === operation.transactionHash &&
    execution?.receipt?.transactionHash === operation.transactionHash &&
    execution?.receipt?.status === operation.receiptStatus &&
    /^(?:0|[1-9][0-9]*)$/.test(execution?.receipt?.gasUsed ?? '') &&
    /^(?:0|[1-9][0-9]*)$/.test(execution?.receipt?.effectiveGasPriceWei ?? '');
}
function sameRecoverySource(left, right) {
  return left && right && left.schema === 'bef-recovery-source/v1' && right.schema === left.schema &&
    left.sourceSnapshotSha256 === right.sourceSnapshotSha256 &&
    left.selectedMeasurementSha256 === right.selectedMeasurementSha256 &&
    left.sourceResponseSha256 === right.sourceResponseSha256 &&
    Object.keys(left).sort().join(',') === 'schema,selectedMeasurementSha256,sourceResponseSha256,sourceSnapshotSha256' &&
    Object.keys(right).sort().join(',') === 'schema,selectedMeasurementSha256,sourceResponseSha256,sourceSnapshotSha256';
}

async function readonly(pool, callback, expectedDatabase = null, expectedRole = 'oid_observer') {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS read_only,clock_timestamp() AS database_now`)).rows[0];
    if (identity?.role !== expectedRole || identity.read_only !== 'on' ||
        (expectedDatabase && identity.database_name !== expectedDatabase)) throw new Error('recovery_observer_identity_invalid');
    const result = await callback(client, identity);
    await client.query('COMMIT');
    return { identity: { role: identity.role, databaseName: identity.database_name,
      transactionReadOnly: identity.read_only, databaseNow: new Date(identity.database_now).toISOString() }, result };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function makeBefObserverPool() {
  let password;
  try { password = (await readFile('/run/secrets/bef_database_observer_password', 'utf8')).trim(); }
  catch { throw new Error('recovery_bef_observer_secret_unavailable'); }
  demand(password.length >= 16 && !/[\r\n\u0000]/.test(password), 'recovery_bef_observer_secret_invalid');
  const port = Number(process.env.BEF_DATABASE_HOST_PORT ?? '55432');
  demand(Number.isSafeInteger(port) && port >= 1 && port <= 65535, 'recovery_bef_observer_port_invalid');
  const url = new URL(`postgres://bef_observer@host.docker.internal:${port}/bef`);
  url.password = password;
  password = '';
  return new Pool({ connectionString: url.href, max: 1, application_name: 'bpc-platform-recovery-readonly-observer',
    connectionTimeoutMillis: 10_000, query_timeout: 15_000 });
}

async function readOwnerRecoverySnapshot(pool, target) {
  const captured = await readonly(pool, async (client) => {
    const run = pgRows((await client.query(`SELECT id::text,owner_id::text,agent_id::text,mode,status,terminal_reason,
        cancellation_reason,cancellation_evidence_hash,started_at::text,finished_at::text,environment_id,task_ids
      FROM oid_benchmark_run WHERE id=$1`, [target.runId])).rows);
    const actions = pgRows((await client.query(`SELECT a.id::text,a.task_index,a.action_sequence::text,a.operation_id,a.action_kind,
        a.payload_hash,a.environment_id,a.accepted_at::text,r.receipt_revision,r.receipt_status,r.evidence_hash,
        r.evidence_path,r.transaction_hash,r.tool_response_hash,o.status AS outbox_status,o.delivered_at::text
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      JOIN oid_run_task_action_outbox o ON o.action_id=a.id WHERE a.run_id=$1 ORDER BY a.action_sequence`, [target.runId])).rows);
    const tasks = pgRows((await client.query(`SELECT task_index,task_id,status,closure_status,closure_reason,started_at::text,
        finished_at::text,deadline_at::text
      FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`, [target.runId])).rows);
    const execution = pgRows((await client.query(`SELECT b.run_id::text,b.task_index,b.env_id,b.generation_id::text,b.participant_id,b.payer_address,
        i.preparation_id::text,i.lease_id::text,l.state AS lease_state,l.fence_evidence AS lease_fence_evidence
      FROM oid_task_execution_binding b
      LEFT JOIN oid_task_preparation_intent i ON i.run_id=b.run_id AND i.task_index=b.task_index
      LEFT JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      WHERE b.run_id=$1 ORDER BY b.task_index`, [target.runId])).rows);
    const evaluations = pgRows((await client.query(`SELECT task_index,task_id,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index`, [target.runId])).rows).map((row) => {
      let result = null;
      try { result = typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json; } catch { /* hash facts remain */ }
      return { taskIndex: row.task_index, taskId: row.task_id, resultHash: row.result_hash,
        evaluatorSourceHash: row.evaluator_source_hash, outcomeStatus: result?.status ?? null,
        outcome: result?.outcome ?? null, credit: result?.credit ?? null,
        mandatoryViolationPresent: result && Object.hasOwn(result, 'mandatoryViolation')
          ? result.mandatoryViolation !== null : null };
    });
    const recovery = pgRows((await client.query(`SELECT action_id::text,run_id::text,owner_id::text,agent_id::text,task_index,
        environment_id,operation_id,payload_hash,incident_evidence_hash,started_at::text,deadline_at::text,
        clock_excluded_ms,status,latest_evidence_hash
      FROM oid_run_platform_recovery WHERE action_id=$1 AND run_id=$2`, [target.actionId, target.runId])).rows);
    const recoveryObservations = pgRows((await client.query(`SELECT evidence_hash,receipt_status,clock_excluded_ms,observed_at::text
      FROM oid_run_platform_recovery_observation WHERE action_id=$1 ORDER BY observed_at,evidence_hash`, [target.actionId])).rows);
    const refunds = pgRows((await client.query(`SELECT run_id::text,evidence_hash,operation_id,bonus_refunded_units::text,created_at::text
      FROM oid_run_platform_refund WHERE run_id=$1`, [target.runId])).rows);
    const refundOperationId = 'runref_' + target.runId.replaceAll('-', '');
    const refundAudits = pgRows((await client.query(`SELECT event_type,operation_id,actor_owner_id::text,subject_owner_id::text,
        metadata->>'runId' AS run_id,metadata->>'evidenceHash' AS evidence_hash,
        metadata->>'bonusRefundedUnits' AS bonus_refunded_units,metadata->>'originalActionId' AS original_action_id,
        metadata->>'originalOperationId' AS original_operation_id
      FROM oid_ledger_audit WHERE operation_id=$1 AND event_type='run_platform_failure_refunded'`, [refundOperationId])).rows);
    const claims = pgRows((await client.query(`SELECT run_id::text,claim_id::text,status,claimed_at::text,released_at::text
      FROM oid_run_dispatch_claim WHERE run_id=$1 ORDER BY claimed_at`, [target.runId])).rows);
    const slots = pgRows((await client.query(`SELECT run_id::text,agent_id::text,claim_id::text,state,acquired_at::text,released_at::text
      FROM oid_run_execution_slot WHERE run_id=$1 ORDER BY acquired_at`, [target.runId])).rows);
    const reservations = pgRows((await client.query(`SELECT id::text,source_kind,bonus_grant_id::text,cash_provenance,
        amount_units::text,state FROM oid_run_reservation WHERE run_id=$1 ORDER BY id`, [target.runId])).rows);
    const holds = pgRows((await client.query(`SELECT run_id::text,mode,amount_units::text,state FROM oid_run_budget_hold WHERE run_id=$1`,
      [target.runId])).rows);
    const ledgerOperationIds = ['runacc_' + target.runId.replaceAll('-', ''), 'rundeb_' + target.runId.replaceAll('-', ''),
      'runrel_' + target.runId.replaceAll('-', '')];
    const refundPrefix = 'runref_' + target.runId.replaceAll('-', '') + '_';
    const ledger = pgRows((await client.query(`SELECT entry_type,source_kind,operation_id,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,bonus_grant_id::text
      FROM oid_ledger_entry WHERE operation_id=ANY($1::text[]) OR left(operation_id,length($2))=$2
      ORDER BY operation_id,id`, [ledgerOperationIds, refundPrefix])).rows);
    const events = pgRows((await client.query(`SELECT sequence::text,source,event_type,payload_hash,created_at::text
      FROM oid_run_event WHERE run_id=$1 ORDER BY sequence`, [target.runId])).rows.map((row) => {
      return { sequence: row.sequence, source: row.source, eventType: row.event_type,
        payloadHash: row.payload_hash, createdAt: row.created_at };
    }));
    const terminalEvents = pgRows((await client.query(`SELECT run_id::text,id::text,sequence::text,event_type,payload_hash,
        payload_json->>'reason' AS reason,payload_json->>'fenceEvidenceHash' AS fence_evidence_hash,
        payload_json->>'actionId' AS action_id,payload_json->>'operationId' AS operation_id,
        payload_json->>'evidenceHash' AS evidence_hash,payload_json->>'bonusRefundedUnits' AS bonus_refunded_units,
        payload_json->>'cashRefundedUnits' AS cash_refunded_units,created_at::text
      FROM oid_run_event WHERE run_id=$1 AND event_type IN
        ('run.cancelled.after_start','run.failed.platform_recovery_exhausted') ORDER BY sequence`, [target.runId])).rows);
    return { run: run[0] ?? null, actions, tasks, execution, evaluations, recovery: recovery[0] ?? null,
      recoveryObservations, refunds, refundAudits, claims, slots, reservations, holds, ledger, events, terminalEvents };
  }, target.databaseName);
  return captured;
}

async function readBefAction(pool, expected) {
  const keyHash = hash(`task-action-${expected.actionId}`);
  const { canonicalTaskJson } = await import('../../owner-identity/dist/task-release.js');
  const { makeRecoverySourceEvidence, hashRecoverySourceMeasurement } =
    await import('../../owner-identity/dist/beta-platform-recovery-source-evidence.js');
  const captured = await readonly(pool, async (client) => {
    const rows = pgRows((await client.query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,o.participant_id,
        o.idempotency_key_sha256,o.request_sha256,o.operation_kind,o.status,o.transaction_hash,o.receipt_status,
        o.response_sha256,o.completed_at::text,g.status AS generation_status,g.fenced_at::text,
        trim(g.manifest_sha256) AS generation_manifest_sha256,trim(e.manifest_sha256) AS environment_manifest_sha256
      FROM public.bef_operation o JOIN public.bef_generation g
        ON g.env_id=o.env_id AND g.generation_id=o.generation_id
      JOIN public.bef_environment e ON e.env_id=o.env_id
      WHERE o.env_id=$1 AND o.generation_id=$2::uuid AND o.participant_id=$3 AND o.idempotency_key_sha256=$4`,
    [expected.environmentId, expected.generationId, expected.participantId, keyHash])).rows);
    demand(rows.length === 1, 'recovery_source_operation_not_unique');
    const row = rows[0];
    const operation = { operationId: String(row.operation_id).toLowerCase(), environmentId: row.env_id,
      generationId: row.generation_id, participantIdSha256: hash(row.participant_id),
      idempotencyKeySha256: String(row.idempotency_key_sha256).trim().toLowerCase(), requestSha256: String(row.request_sha256).trim().toLowerCase(),
      operationKind: row.operation_kind, status: row.status,
      transactionHash: typeof row.transaction_hash === 'string' ? row.transaction_hash.toLowerCase() : null,
      receiptStatus: row.receipt_status, responseSha256: row.response_sha256,
      completedAt: row.completed_at, generationStatus: row.generation_status, fencedAt: row.fenced_at };
    const selectedRows = pgRows((await client.query(`SELECT action_kind,selected_action_json,transaction_hash,outcome,measurement_json
      FROM public.bef_selected_execution WHERE operation_id=$1::uuid AND env_id=$2 AND generation_id=$3::uuid LIMIT 2`,
    [row.operation_id, row.env_id, row.generation_id])).rows);
    const eventRows = pgRows((await client.query(`SELECT event_kind,event_json
      FROM public.bef_selected_execution_event WHERE operation_id=$1::uuid AND env_id=$2 AND generation_id=$3::uuid
        AND event_kind='selected_action_bound' ORDER BY event_sequence LIMIT 2`,
    [row.operation_id, row.env_id, row.generation_id])).rows);
    demand(selectedRows.length === 1 && eventRows.length === 1, 'recovery_source_selection_not_unique');
    const selected = selectedRows[0];
    const selectedAction = jsonObject(selected.selected_action_json, 'recovery_source_selected_action_invalid');
    const measurement = jsonObject(selected.measurement_json, 'recovery_source_measurement_invalid');
    const eventJson = jsonObject(eventRows[0].event_json, 'recovery_source_selected_event_invalid');
    assertSecretFree(measurement, 'recovery_source_measurement');
    assertSecretFree(eventJson, 'recovery_source_selected_event');
    const eventSha256 = canonicalHash(eventJson, canonicalTaskJson);
    const selectedActionSha256 = canonicalHash(selectedAction, canonicalTaskJson);
    const selectedEventAction = jsonObject(eventJson.selectedAction, 'recovery_source_event_action_invalid');
    const selectedEventActionSha256 = canonicalHash(selectedEventAction, canonicalTaskJson);
    const receipt = jsonObject(measurement.receipt, 'recovery_source_receipt_invalid');
    const selectedMeasurementSha256 = hashRecoverySourceMeasurement(measurement).toLowerCase();
    const selectedTransactionHash = typeof selected.transaction_hash === 'string' ? selected.transaction_hash.toLowerCase() : null;
    const transactionHash = typeof row.transaction_hash === 'string' ? row.transaction_hash.toLowerCase() : null;
    const receiptTransactionHash = typeof receipt.transactionHash === 'string' ? receipt.transactionHash.toLowerCase() : null;
    const receiptGasUsed = decimalQuantity(receipt.gasUsed);
    const receiptEffectiveGasPriceWei = decimalQuantity(receipt.effectiveGasPrice);
    const selectedOutcome = selected.outcome;
    const expectedActionKind = RECOVERY_FIRST_ACTION_KIND[expected.taskId];
    demand(expectedActionKind && expected.actionKind === expectedActionKind &&
      row.status === 'settled' && row.receipt_status === 'success' && row.operation_kind === expectedActionKind &&
      selected.action_kind === row.operation_kind && selectedOutcome === 'success' &&
      /^0x[0-9a-f]{64}$/.test(transactionHash ?? '') && selectedTransactionHash === transactionHash &&
      receiptTransactionHash === transactionHash && receipt.status === 'success' &&
      receiptGasUsed !== null && receiptEffectiveGasPriceWei !== null &&
      eventRows[0].event_kind === 'selected_action_bound' && Object.keys(eventJson).sort().join(',') ===
        'actionKind,requestSha256,selectedAction' && eventJson.actionKind === row.operation_kind &&
      typeof eventJson.requestSha256 === 'string' && eventJson.requestSha256.toLowerCase() === String(row.request_sha256).toLowerCase() &&
      selectedEventActionSha256 === selectedActionSha256 && SHA256.test(row.generation_manifest_sha256 ?? '') &&
      SHA256.test(row.environment_manifest_sha256 ?? ''), 'recovery_source_selection_binding_invalid');
    const recoverySource = makeRecoverySourceEvidence({
      operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
      participantId: row.participant_id, idempotencyKeySha256: String(row.idempotency_key_sha256).trim(),
      requestSha256: String(row.request_sha256).trim(), operationKind: row.operation_kind, status: row.status,
      transactionHash, receiptStatus: row.receipt_status,
      responseSha256: row.response_sha256 === null ? null : String(row.response_sha256).trim(),
      generationManifestSha256: String(row.generation_manifest_sha256).trim(),
      environmentManifestSha256: String(row.environment_manifest_sha256).trim(),
      selectedActionKind: selected.action_kind, selectedActionEventCount: eventRows.length,
      selectedActionEventKind: eventJson.actionKind,
      selectedActionEventRequestSha256: eventJson.requestSha256,
      selectedActionEventSha256: eventSha256, selectedOutcome,
      selectedTransactionHash, selectedMeasurementSha256,
    });
    demand(recoverySource && recoverySource.sourceResponseSha256 === null,
      'recovery_source_proof_unavailable');
    return { operations: [operation], recoverySource, selectedExecutions: [{
      operationId: row.operation_id, selectedActionKind: selected.action_kind,
      selectedActionSha256, selectedOutcome, selectedTransactionHash,
      selectedMeasurementSha256, selectedActionEventCount: eventRows.length,
      selectedActionEventKind: eventRows[0].event_kind,
      selectedActionEventActionKind: eventJson.actionKind,
      selectedActionEventRequestSha256: eventJson.requestSha256.toLowerCase(),
      selectedActionEventSelectedActionSha256: selectedEventActionSha256,
      selectedActionEventSha256: eventSha256,
      generationManifestSha256: String(row.generation_manifest_sha256).toLowerCase(),
      environmentManifestSha256: String(row.environment_manifest_sha256).toLowerCase(),
      receipt: { transactionHash, status: receipt.status, gasUsed: receiptGasUsed,
        effectiveGasPriceWei: receiptEffectiveGasPriceWei },
    }] };
  }, 'bef', 'bef_observer');
  return { ...captured, result: captured.result.operations, keySha256: keyHash,
    operations: captured.result.operations, recoverySource: captured.result.recoverySource,
    selectedExecutions: captured.result.selectedExecutions };
}

export function recoveryDeadlineObservationState(row, databaseNow) {
  demand(row && typeof row === 'object' &&
    ['recovering', 'unknown', 'exhausted', 'refunded'].includes(row.status),
  'recovery_exhaustion_status_invalid');
  const startedMs = Date.parse(row.started_at);
  const deadlineMs = Date.parse(row.deadline_at);
  const databaseNowMs = Date.parse(databaseNow);
  demand(Number.isFinite(startedMs) && Number.isFinite(deadlineMs) && Number.isFinite(databaseNowMs) &&
    deadlineMs === startedMs + RECOVERY_WINDOW_MS,
  'recovery_deadline_identity_invalid');
  if (['exhausted', 'refunded'].includes(row.status)) {
    demand(databaseNowMs >= deadlineMs, 'recovery_exhaustion_terminal_state_pre_deadline');
  }
  return { startedMs, deadlineMs, databaseNowMs, deadlineReached: databaseNowMs >= deadlineMs + 1_000 };
}

export function recoveryExhaustionTerminalConditions(snapshot) {
  const result = snapshot?.result ?? {};
  const slots = Array.isArray(result.slots) ? result.slots : [];
  const claims = Array.isArray(result.claims) ? result.claims : [];
  const executions = Array.isArray(result.execution) ? result.execution : [];
  const cancellationEvents = Array.isArray(result.terminalEvents)
    ? result.terminalEvents.filter((row) => row.event_type === 'run.cancelled.after_start') : [];
  const runId = result.run?.id;
  const releasedClaimIds = new Set(claims.filter((row) => row.run_id === runId && row.status === 'released' &&
    row.released_at !== null && UUID.test(row.claim_id ?? '')).map((row) => row.claim_id));
  const exactReleasedClaimSet = claims.length > 0 && releasedClaimIds.size === claims.length;
  const slotDispositionSafe = Array.isArray(result.slots) && (slots.length === 0 ||
    (slots.length === 1 && slots[0].run_id === runId && slots[0].agent_id === result.run?.agent_id &&
      slots[0].state === 'released' && slots[0].released_at !== null && releasedClaimIds.has(slots[0].claim_id)));
  const execution = executions.length === 1 ? executions[0] : null;
  const fence = execution?.lease_fence_evidence;
  const exactLeaseFence = execution?.run_id === runId && execution?.lease_state === 'fenced' &&
    fence?.confirmed === true && fence.preparationId === execution.preparation_id &&
    fence.leaseId === execution.lease_id && fence.environmentId === execution.env_id &&
    fence.generationId === execution.generation_id &&
    fence.evidence?.boundary === 'actual_tool_http_x402_local_evm_application_store' &&
    SHA256.test(fence.evidence?.sha256 ?? '');
  const exactCancellationFenceEvent = cancellationEvents.length === 1 &&
    cancellationEvents[0].run_id === runId && cancellationEvents[0].reason === 'coordinator_platform_failure' &&
    cancellationEvents[0].fence_evidence_hash === result.run?.cancellation_evidence_hash &&
    SHA256.test(result.run?.cancellation_evidence_hash ?? '') &&
    result.run?.cancellation_reason === 'coordinator_platform_failure';
  const conditions = {
    runFailed: result.run?.status === 'failed',
    exhaustionTerminalReason: result.run?.terminal_reason === 'platform_failure_recovery_exhausted',
    recoveryRefunded: result.recovery?.status === 'refunded',
    exactlyOneRefund: Array.isArray(result.refunds) && result.refunds.length === 1,
    noActiveExecutionSlot: slotDispositionSafe,
    firstDispatchClaimReleasedAndRunBound: exactReleasedClaimSet,
    generationLeaseFenced: exactLeaseFence,
    cancellationFenceEventBound: exactCancellationFenceEvent,
  };
  const failedConditions = Object.entries(conditions).filter(([, satisfied]) => !satisfied).map(([name]) => name);
  return { conditions, failedConditions, verified: failedConditions.length === 0 };
}

export async function waitForRecoveryExhaustionFinalization(readSnapshot, { runId, actionId,
  maxWaitMs = 30_000, pollIntervalMs = 750, now = Date.now,
  sleep = (durationMs) => new Promise((done) => setTimeout(done, durationMs)) } = {}) {
  demand(typeof readSnapshot === 'function' && UUID.test(runId ?? '') && UUID.test(actionId ?? '') &&
    Number.isSafeInteger(maxWaitMs) && maxWaitMs >= 1 && maxWaitMs <= 60_000 &&
    Number.isSafeInteger(pollIntervalMs) && pollIntervalMs >= 1 && pollIntervalMs <= 5_000 &&
    typeof now === 'function' && typeof sleep === 'function', 'recovery_finalization_wait_invalid');
  const startedAt = now();
  let latestSnapshot = null;
  let latestState = null;
  for (;;) {
    const state = await readSnapshot();
    latestSnapshot = state?.snapshot ?? state;
    latestState = recoveryExhaustionTerminalConditions(latestSnapshot);
    const elapsedMs = Math.max(0, now() - startedAt);
    if (latestState.verified) return { snapshot: latestSnapshot, elapsedMs, ...latestState };
    if (elapsedMs >= maxWaitMs) {
      const result = latestSnapshot?.result ?? {};
      throw Object.assign(new Error('platform_recovery_exhaustion_terminal_wait_timeout'), {
        code: 'PLATFORM_RECOVERY_EXHAUSTION_FINALIZATION_TIMEOUT',
        safeDiagnostic: { schemaVersion: 'bpc-recovery-finalization-timeout/v1', runId, actionId,
          elapsedMs, maxWaitMs, conditions: latestState.conditions, failedConditions: latestState.failedConditions,
          current: { runStatus: result.run?.status ?? null, terminalReason: result.run?.terminal_reason ?? null,
            recoveryStatus: result.recovery?.status ?? null, refundCount: Array.isArray(result.refunds) ? result.refunds.length : null,
            executionSlotCount: Array.isArray(result.slots) ? result.slots.length : null,
            unreleasedExecutionSlotCount: Array.isArray(result.slots)
              ? result.slots.filter((row) => row.released_at === null).length : null,
            dispatchClaimCount: Array.isArray(result.claims) ? result.claims.length : null,
            unreleasedDispatchClaimCount: Array.isArray(result.claims)
              ? result.claims.filter((row) => row.released_at === null).length : null,
            unfencedGenerationLeaseCount: Array.isArray(result.execution)
              ? result.execution.filter((row) => row.lease_state !== 'fenced').length : null } },
      });
    }
    await sleep(Math.min(pollIntervalMs, maxWaitMs - elapsedMs));
  }
}

function activeBinding(snapshot, { taskId = 'S1', actionId = null, actionOrdinal = 0 } = {}) {
  const tasks = snapshot?.result?.tasks;
  const actions = snapshot?.result?.actions;
  const executions = snapshot?.result?.execution;
  demand(Array.isArray(tasks) && tasks.length === 1 && tasks[0].task_index === 0 && tasks[0].task_id === taskId &&
    Array.isArray(actions) && actions.length > 0 && Array.isArray(executions) && executions.length === 1 &&
    Number.isSafeInteger(actionOrdinal) && actionOrdinal >= 0,
  'recovery_action_generation_binding_missing');
  const execution = executions[0];
  const taskActions = actions.filter((row) => row?.task_index === 0);
  demand(taskActions.length === actions.length && execution.task_index === 0 &&
    UUID.test(execution.generation_id ?? '') && UUID.test(execution.preparation_id ?? '') &&
    typeof execution.env_id === 'string' && execution.env_id.length > 0,
  'recovery_action_generation_binding_missing');
  const sequenceValues = taskActions.map((row) => {
    demand(typeof row.action_sequence === 'string' && /^(?:0|[1-9][0-9]*)$/.test(row.action_sequence),
      'recovery_action_sequence_invalid');
    return BigInt(row.action_sequence);
  });
  demand(new Set(sequenceValues.map(String)).size === sequenceValues.length, 'recovery_action_sequence_duplicate');
  const orderedActions = taskActions.slice().sort((left, right) => {
    const a = BigInt(left.action_sequence);
    const b = BigInt(right.action_sequence);
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const action = actionId === null ? orderedActions[actionOrdinal] :
    orderedActions.find((row) => row.id === actionId);
  demand(action && (actionId === null || action.id === actionId) &&
    (!actionId || action.id === orderedActions[actionOrdinal]?.id) && UUID.test(action.id ?? '') &&
    typeof action.operation_id === 'string' && action.operation_id.length > 0 &&
    SHA256.test(action.payload_hash ?? '') && action.environment_id === execution.env_id &&
    action.action_kind === RECOVERY_FIRST_ACTION_KIND[taskId],
  'recovery_action_generation_binding_missing');
  return { actionId: action.id, operationId: action.operation_id, payloadHash: action.payload_hash,
    actionKind: action.action_kind, taskId, taskIndex: 0,
    environmentId: execution.env_id, generationId: execution.generation_id,
    preparationId: execution.preparation_id, participantId: execution.participant_id,
    leaseId: execution.lease_id };
}

export function selectRecoveryActionBinding(snapshot, options = {}) {
  return activeBinding(snapshot, options);
}

async function verifyEvidenceReference(repoRoot, reference, code) {
  if (!reference || typeof reference.path !== 'string' || !SHA256.test(reference.sha256 ?? '') ||
      reference.path.includes('\\') || reference.path.startsWith('/') || /^[A-Za-z]:/.test(reference.path) ||
      reference.path.split('/').some((part) => !part || part === '.' || part === '..')) {
    demand(false, code + '_shape_invalid');
  }
  const absolutePath = resolve(repoRoot, ...reference.path.split('/'));
  const relativePath = relative(repoRoot, absolutePath);
  demand(!isAbsolute(relativePath) && relativePath !== '..' && !relativePath.startsWith('..' + sep), code + '_path_escape');
  const bytes = await readFile(absolutePath);
  demand(hash(bytes) === reference.sha256, code + '_hash_mismatch');
  return { path: reference.path, sha256: reference.sha256, bytes: bytes.length };
}

async function readEvidenceDocument(repoRoot, reference, code) {
  const verified = await verifyEvidenceReference(repoRoot, reference, code);
  const bytes = await readFile(resolve(repoRoot, ...reference.path.split('/')));
  let document;
  try { document = JSON.parse(bytes.toString('utf8')); } catch { demand(false, code + '_json_invalid'); }
  demand(document && typeof document === 'object' && !Array.isArray(document), code + '_shape_invalid');
  assertSecretFree(document, code);
  return { reference: verified, document };
}

function compactGenuine(outcome) {
  return { captureId: outcome.captureId, status: outcome.status, classification: outcome.classification,
    ownerId: outcome.ownerId, agentId: outcome.agent?.agentId ?? null, intentId: outcome.launchIntent?.intentId ?? null,
    runId: outcome.run?.runId ?? outcome.runId ?? null, mode: outcome.mode, taskIds: outcome.taskIds,
    bonusFunding: outcome.bonusGrant ? { codeId: outcome.bonusGrant.codeId, grantId: outcome.bonusGrant.grantId,
      grantOperationId: outcome.bonusGrant.operationId, amountUnits: outcome.bonusGrant.amountUnits,
      sourceKind: outcome.bonusGrant.sourceKind } : null,
    evaluation: Array.isArray(outcome.taskEvaluations) ? outcome.taskEvaluations.map((row) => ({
      taskIndex: row.taskIndex, taskId: row.taskId, resultHash: row.resultHash,
      resultStatus: row.result?.status ?? null, outcome: row.result?.outcome ?? null, credit: row.result?.credit ?? null,
    })) : [],
    runCompletion: outcome.trainingRunCompletion ? { status: outcome.trainingRunCompletion.status,
      runStatus: outcome.trainingRunCompletion.runStatus, gradePublished: outcome.taskGradePublished === true } : null,
  };
}

async function progress(progressFn, value) {
  if (typeof progressFn === 'function') await progressFn({ component: 'beta_platform_recovery', ...value });
}

async function persistGenuineAttempt(commonCapture, name, output) {
  const directory = resolve(commonCapture.repoRoot, 'artifacts/runs/beta-platform-recovery-source', commonCapture.runId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  assertSecretFree(output, 'recovery-genuine-attempt');
  const bytes = Buffer.from(`${JSON.stringify(output, null, 2)}\n`);
  const path = resolve(directory, `${name}-${output.captureId}.json`);
  await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
  return { path: relative(commonCapture.repoRoot, path).split(sep).join('/'), sha256: hash(bytes), bytes: bytes.length };
}

async function runRecoveredCommittedAction(commonCapture, recoveryFaultProxy, progressFn,
  { taskId = 'S1', onGenuineRunCompleted, requirePassingEvaluation = false } = {}) {
  const captureId = randomUUID();
  const ownerPool = new Pool({ connectionString: commonCapture.observerDatabaseUrl, max: 1,
    application_name: 'bpc-recovery-owner-snapshot' });
  const befPool = await makeBefObserverPool();
  let proxyArmed = false;
  const recoveryFault = {
    waitTimeoutMs: 210_000,
    beforeFirstAction: async () => { recoveryFaultProxy.arm(); proxyArmed = true; },
    onInitialUnknown: async (event) => progress(progressFn, { phase: 'committed_action_response_lost',
      runId: event.runId, actionId: event.actionId, receiptStatus: event.action?.receiptStatus ?? 'unknown',
      retrySubmitted: false }),
  };
  try {
    const output = await runGenuineS1OwnerCase({ ...commonCapture.genuineCaptureInput, captureId,
      mode: 'training', taskId, automaticWorkerEvaluation: true, bonusCodeFunding: true,
      bddProbes: false, primaryClientOnly: false, platformRecoveryFault: recoveryFault,
      ...(typeof onGenuineRunCompleted === 'function' ? { onGenuineRunCompleted } : {}) });
    const genuineAttempt = await persistGenuineAttempt(commonCapture,
      taskId === 'S1' ? 'recovered' : 'collector-' + taskId.toLowerCase(), output);
    if (!(output.status === 'captured_' + taskId.toLowerCase() + '_training_run_completed_by_server_worker' &&
        output.trainingRunCompletion?.status === 'verified' && output.taskGradePublished === false &&
        UUID.test(output.run?.runId ?? '') && Array.isArray(output.taskIds) && output.taskIds.length === 1 &&
        output.taskIds[0] === taskId)) {
      throw Object.assign(new Error('recovery_success_run_not_completed_by_real_worker'), {
        code: 'RECOVERY_GENUINE_RUN_INCOMPLETE', safeDiagnostic: { genuineAttempt,
          status: output.status, blocker: output.blocker ?? null, stages: output.stages?.slice(-8) ?? [] } });
    }
    const runId = output.run.runId;
    const initialUnknownActionId = output.platformRecovery?.initialUnknown?.actionId;
    demand(UUID.test(initialUnknownActionId ?? ''), 'recovery_success_initial_unknown_action_missing');
    const initialWithoutRecovery = await readOwnerRecoverySnapshot(ownerPool, {
      databaseName: commonCapture.databaseIsolation.databaseName, runId });
    const firstBinding = activeBinding(initialWithoutRecovery, { taskId, actionId: initialUnknownActionId, actionOrdinal: 0 });
    const initial = await readOwnerRecoverySnapshot(ownerPool, { databaseName: commonCapture.databaseIsolation.databaseName,
      runId, actionId: firstBinding.actionId });
    const binding = activeBinding(initial, { taskId, actionId: initialUnknownActionId, actionOrdinal: 0 });
    demand(output.platformRecovery?.initialUnknown?.actionId === binding.actionId &&
      output.platformRecovery.reconciledOriginalAction?.finalReceiptStatus === 'observed' &&
      output.platformRecovery.reconciledOriginalAction?.resubmissionCount === 0,
    'recovery_success_original_action_not_reconciled');
    const action = initial.result.actions.find((row) => row.id === binding.actionId);
    const taskEvaluation = output.taskEvaluations?.length === 1 ? output.taskEvaluations[0] : null;
    const persistedEvaluation = initial.result.evaluations.length === 1 ? initial.result.evaluations[0] : null;
    if (requirePassingEvaluation) {
      demand(taskEvaluation?.taskIndex === 0 && taskEvaluation.taskId === taskId &&
        taskEvaluation.result?.status === 'known' && taskEvaluation.result?.outcome === 'passed' &&
        taskEvaluation.result?.mandatoryViolation === null && taskEvaluation.result?.credit?.numerator === '1' &&
        taskEvaluation.result?.credit?.denominator === '1' &&
        persistedEvaluation?.taskIndex === 0 && persistedEvaluation.taskId === taskId &&
        persistedEvaluation.outcomeStatus === 'known' && persistedEvaluation.outcome === 'passed' &&
        persistedEvaluation.credit?.numerator === '1' && persistedEvaluation.credit?.denominator === '1' &&
        persistedEvaluation.mandatoryViolationPresent === false,
      'recovery_collector_task_evaluation_not_passing');
    }
    demand(action && action.receipt_status === 'observed' && action.outbox_status === 'delivered' &&
      initial.result.recovery?.status === 'recovered' && initial.result.refunds.length === 0 &&
      initial.result.run.status === 'completed' && initial.result.tasks.length === 1 &&
      initial.result.tasks[0].task_index === 0 && initial.result.tasks[0].task_id === taskId &&
      initial.result.evaluations.length === 1,
    'recovery_success_durable_effects_mismatch');
    const source = await readBefAction(befPool, { ...binding, participantId: binding.participantId,
      taskId, actionKind: action.action_kind });
    demand(source.result.length === 1 && source.result[0].environmentId === binding.environmentId &&
      source.result[0].generationId === binding.generationId && source.result[0].status === 'settled' &&
      source.result[0].operationKind === action.action_kind &&
      source.result[0].generationStatus === 'fenced' &&
      /^0x[0-9a-f]{64}$/i.test(source.result[0].transactionHash ?? '') &&
      source.result[0].responseSha256 === null && source.result[0].idempotencyKeySha256 === source.keySha256 &&
      recoverySourceBound(source),
    'recovery_success_source_operation_not_exactly_bound');
    const proxy = recoveryFaultProxy.snapshot();
    const actionSubmissions = proxy.submissions.filter((row) => row.actionId === binding.actionId);
    demand(proxy.fault?.actionId === binding.actionId && proxy.fault.upstreamStatus >= 200 &&
      proxy.fault.upstreamStatus < 300 && proxy.fault.upstreamResponseComplete === true &&
      proxy.fault.downstreamResponseDelivered === false && proxy.submissions.filter((row) => row.actionId === binding.actionId)
        .length === 1 && actionSubmissions[0]?.count === 1, 'recovery_success_fault_boundary_or_no_replay_missing');
    const execution = initial.result.execution.find((row) => row.task_index === 0);
    const evidenceCapture = action.evidence_path && action.evidence_hash
      ? await readEvidenceDocument(commonCapture.repoRoot,
        { path: action.evidence_path, sha256: action.evidence_hash }, 'recovery_action_evidence') : null;
    demand(evidenceCapture?.document?.reasonCode === 'platform_recovery_original_operation_terminal' &&
      evidenceCapture.document.befOperationId === source.result[0].operationId &&
      evidenceCapture.document.transactionHash?.toLowerCase() === source.result[0].transactionHash?.toLowerCase() &&
      evidenceCapture.document.receiptStatus === source.result[0].receiptStatus &&
      evidenceCapture.document.outcome === source.result[0].receiptStatus &&
      sameRecoverySource(evidenceCapture.document.recoverySource, source.recoverySource) &&
      !Object.hasOwn(evidenceCapture.document, 'httpStatus') && !Object.hasOwn(evidenceCapture.document, 'rawResponseSha256') &&
      String(evidenceCapture.document.receiptGasUsed) === source.selectedExecutions[0].receipt.gasUsed &&
      String(evidenceCapture.document.receiptEffectiveGasPriceWei) === source.selectedExecutions[0].receipt.effectiveGasPriceWei,
    'recovery_success_action_evidence_not_source_reconciled');
    const evidence = evidenceCapture.reference;
    const fenceReference = await verifyEvidenceReference(commonCapture.repoRoot,
      execution.lease_fence_evidence?.evidence, 'recovery_success_fence_evidence');
    return { schemaVersion: 'bpc-platform-recovery-case/v1', captureId, genuineAttempt, status: 'verified_local_recovery',
      boundary: 'real_owner_ui_bonus_code_real_bef_action_response_dropped_then_server_monitor_reconciled',
      genuineRun: compactGenuine(output), action: { actionId: binding.actionId, ownerOperationId: binding.operationId,
        taskIndex: action.task_index, actionSequence: action.action_sequence, kind: action.action_kind,
        payloadHash: action.payload_hash, initialReceiptStatus: 'unknown', finalReceiptStatus: action.receipt_status,
        outboxStatus: action.outbox_status,
        upstreamSubmissionCount: actionSubmissions.find((row) => row.actionId === binding.actionId)?.count ?? null, evidence },
      binding: { runId, ownerId: initial.result.run.owner_id, agentId: initial.result.run.agent_id,
        mode: initial.result.run.mode, taskId,
        environmentId: binding.environmentId, preparationId: binding.preparationId, generationId: binding.generationId,
        participantIdSha256: hash(binding.participantId), leaseId: binding.leaseId },
      recovery: { ...initial.result.recovery, observations: initial.result.recoveryObservations,
        refundCount: initial.result.refunds.length, sourceOperationCount: source.result.length },
      beFSource: source, proxy: { ...proxy, upstreamOriginSha256: proxy.upstreamOriginSha256 },
      observer: { identity: initial.identity, runStatus: initial.result.run.status,
        taskRows: initial.result.tasks.map((row) => ({ taskIndex: row.task_index, taskId: row.task_id, status: row.status,
          closureStatus: row.closure_status })), evaluations: initial.result.evaluations, fenceEvidence: fenceReference,
        claims: initial.result.claims, slots: initial.result.slots } };
  } finally {
    if (proxyArmed) {
      const proxy = recoveryFaultProxy.snapshot();
      if (proxy.fault && !proxy.armed) recoveryFaultProxy.resetAfterIncident();
    }
    await ownerPool.end();
    await befPool.end();
  }
}

export async function waitForRecoveryDeadline(pool, target, maxWaitMs, progressFn, testDependencies = {}) {
  const now = testDependencies.now ?? Date.now;
  const sleep = testDependencies.sleep ?? ((durationMs) => new Promise((done) => setTimeout(done, durationMs)));
  const readSnapshot = testDependencies.readSnapshot ?? readOwnerRecoverySnapshot;
  const startedAt = now();
  let nextProgress = startedAt;
  for (;;) {
    if (now() - startedAt > maxWaitMs) throw new Error('recovery_window_wait_exceeded_bound');
    const snapshot = await readSnapshot(pool, target);
    demand(snapshot?.identity?.role === 'oid_observer' && snapshot.identity.transactionReadOnly === 'on' &&
      snapshot.identity.databaseName === target.databaseName, 'recovery_exhaustion_observer_identity_invalid');
    const run = snapshot.result?.run;
    demand(run && typeof run.id === 'string' && run.id.toLowerCase() === target.runId.toLowerCase(),
      'recovery_exhaustion_run_identity_invalid');
    const row = snapshot.result.recovery;
    if (row) {
      demand(typeof row.action_id === 'string' && row.action_id.toLowerCase() === target.actionId.toLowerCase() &&
        typeof row.run_id === 'string' && row.run_id.toLowerCase() === target.runId.toLowerCase(),
      'recovery_exhaustion_record_identity_invalid');
    } else {
      demand(run.status === 'running',
        'recovery_exhaustion_run_terminal_without_record');
      if (now() >= nextProgress) {
        await progress(progressFn, { phase: 'platform_recovery_record_pending', runId: target.runId,
          actionId: target.actionId, elapsedMs: now() - startedAt, observerProxyBlocked: true });
        nextProgress = now() + 15_000;
      }
      if (now() - startedAt > maxWaitMs) throw new Error('recovery_window_wait_exceeded_bound');
      await sleep(750);
      continue;
    }
    const timing = recoveryDeadlineObservationState(row, snapshot.identity.databaseNow);
    // AICODE-NOTE: Fencing can finish while the observer is still blocked. These
    // states permit only the bounded wait; the post-unblock verifier still requires
    // the exact final failure, source receipt, fence and single refund.
    if (['cancellation_requested', 'cancelled', 'failed', 'unknown'].includes(run.status)) {
      demand(timing.databaseNowMs >= timing.deadlineMs, 'recovery_exhaustion_run_terminal_pre_deadline');
    }
    if (run.status === 'cancellation_requested') {
      demand(run.cancellation_reason === 'coordinator_platform_failure', 'recovery_exhaustion_run_terminal_invalid');
    } else if (run.status === 'cancelled') {
      demand(run.cancellation_reason === 'coordinator_platform_failure' &&
        run.terminal_reason === 'coordinator_platform_failure' && SHA256.test(run.cancellation_evidence_hash ?? ''),
      'recovery_exhaustion_run_terminal_invalid');
    } else if (run.status === 'failed') {
      demand(run.terminal_reason === 'platform_failure_recovery_exhausted' &&
        run.cancellation_reason === 'coordinator_platform_failure' && ['exhausted', 'refunded'].includes(row.status),
      'recovery_exhaustion_run_terminal_invalid');
    } else if (run.status === 'unknown') {
      demand(run.terminal_reason === 'platform_recovery_unresolved_operation' &&
        run.cancellation_reason === 'coordinator_platform_failure', 'recovery_exhaustion_run_terminal_invalid');
    } else if (run.status !== 'running') {
      demand(false, 'recovery_exhaustion_run_terminal_invalid');
    }
    if (timing.deadlineReached) return { row, observedAtDatabase: snapshot.identity.databaseNow,
      wallWaitMs: now() - startedAt };
    if (now() >= nextProgress) {
      await progress(progressFn, { phase: 'platform_recovery_window_open', runId: target.runId,
        recoveryStatus: row.status, deadlineAt: new Date(timing.deadlineMs).toISOString(),
        elapsedMs: now() - startedAt, observerProxyBlocked: true });
      nextProgress = now() + 15_000;
    }
    if (now() - startedAt > maxWaitMs) throw new Error('recovery_window_wait_exceeded_bound');
    await sleep(750);
  }
}

async function runExhaustedCommittedAction(commonCapture, recoveryFaultProxy, recoveryObserverProxy, progressFn) {
  const captureId = randomUUID();
  const ownerPool = new Pool({ connectionString: commonCapture.observerDatabaseUrl, max: 1,
    application_name: 'bpc-recovery-exhaustion-owner-snapshot' });
  const befPool = await makeBefObserverPool();
  let proxyArmed = false;
  let restarted = false;
  let restartReceipt;
  let unblocked = false;
  let target;
  let deadlineObservation;
  const readExhaustionTerminalState = async ({ runId, actionId }) => {
    const snapshot = await readOwnerRecoverySnapshot(ownerPool, {
      databaseName: commonCapture.databaseIsolation.databaseName, runId, actionId });
    return { snapshot, conditions: recoveryExhaustionTerminalConditions(snapshot) };
  };
  const recoveryFault = {
    terminalAfterRecovery: true,
    waitTimeoutMs: 235_000,
    beforeFirstAction: async () => {
      recoveryFaultProxy.arm({ onDrop: () => recoveryObserverProxy.block() });
      proxyArmed = true;
    },
    onInitialUnknown: async (event) => {
      target = { databaseName: commonCapture.databaseIsolation.databaseName, runId: event.runId, actionId: event.actionId };
      await progress(progressFn, { phase: 'committed_action_response_lost_observer_blocked', runId: event.runId,
        actionId: event.actionId, receiptStatus: event.action?.receiptStatus ?? 'unknown', retrySubmitted: false });
      if (!restarted) {
        restarted = true;
        restartReceipt = await commonCapture.restartApi();
        await progress(progressFn, { phase: 'owner_api_restarted_during_recovery', runId: event.runId,
          sourceWritesResubmitted: false });
      }
      deadlineObservation = await waitForRecoveryDeadline(ownerPool, target, 205_000, progressFn);
      recoveryObserverProxy.unblock();
      unblocked = true;
      await progress(progressFn, { phase: 'observer_restored_after_original_deadline', runId: event.runId,
        elapsedMs: deadlineObservation.wallWaitMs, deadlineAt: deadlineObservation.row.deadline_at });
    },
    finishWhenUnknown: async ({ runId, actionId }) => {
      return (await readExhaustionTerminalState({ runId, actionId })).conditions.verified;
    },
    afterOriginalActionReconciled: async ({ runId, actionId, action, originalReceiptRemainsUnknown }) => {
      await progress(progressFn, { phase: 'platform_recovery_terminal_finalization_wait_started', runId, actionId,
        maxWaitMs: 30_000, originalReceiptStatus: action?.receiptStatus ?? 'unknown' });
      const terminalFinalization = await waitForRecoveryExhaustionFinalization(
        () => readExhaustionTerminalState({ runId, actionId }), { runId, actionId, maxWaitMs: 30_000 });
      const current = terminalFinalization.snapshot;
      await progress(progressFn, { phase: 'platform_recovery_terminal_finalization_verified', runId, actionId,
        elapsedMs: terminalFinalization.elapsedMs, conditions: terminalFinalization.conditions });
      const sourceAction = current.result.actions.filter((row) => row.id === actionId);
      const source = await readBefAction(befPool, { ...activeBinding(current), actionId });
      const operation = source.result.length === 1 ? source.result[0] : null;
      const recoveryRow = current.result.recovery;
      const eligibleRun = current.result.run;
      const releaseEntries = current.result.ledger.filter((row) => row.entry_type === 'release');
      const refundPrefix = 'runref_' + runId.replaceAll('-', '') + '_';
      const refundEntries = current.result.ledger.filter((row) => row.entry_type === 'refund' && row.operation_id.startsWith(refundPrefix));
      const amount = refundEntries.reduce((sum, row) => sum + BigInt(row.available_delta_units ?? 0) + BigInt(row.expired_delta_units ?? 0), 0n);
      const fenceRows = current.result.execution.filter((row) => row.lease_fence_evidence !== null);
      const fenceEvent = current.result.terminalEvents.filter((row) => row.event_type === 'run.cancelled.after_start');
      const refundEvent = current.result.terminalEvents.filter((row) => row.event_type === 'run.failed.platform_recovery_exhausted');
      const exactFence = fenceRows.length === 1 && fenceRows.every((row) => {
        const fence = row.lease_fence_evidence;
        return row.lease_state === 'fenced' && fence?.confirmed === true &&
          fence.preparationId === row.preparation_id && fence.leaseId === row.lease_id &&
          fence.environmentId === row.env_id && fence.generationId === row.generation_id &&
          fence.evidence?.boundary === 'actual_tool_http_x402_local_evm_application_store' &&
          SHA256.test(fence.evidence?.sha256 ?? '') && fenceEvent.length === 1 &&
          fenceEvent[0].reason === 'coordinator_platform_failure' &&
          fenceEvent[0].fence_evidence_hash === eligibleRun?.cancellation_evidence_hash;
      }) && eligibleRun?.cancellation_reason === 'coordinator_platform_failure' && SHA256.test(eligibleRun?.cancellation_evidence_hash ?? '');
      const fenceEvidenceFiles = [];
      for (const row of fenceRows) fenceEvidenceFiles.push(await verifyEvidenceReference(commonCapture.repoRoot,
        row.lease_fence_evidence?.evidence, 'recovery_exhaustion_fence_evidence'));
      const actionEvidence = sourceAction[0]?.evidence_path && sourceAction[0]?.evidence_hash
        ? await verifyEvidenceReference(commonCapture.repoRoot,
          { path: sourceAction[0].evidence_path, sha256: sourceAction[0].evidence_hash }, 'recovery_exhaustion_action_evidence')
        : null;
      const finalizationConditions = recoveryExhaustionTerminalConditions(current);
      const noGrade = current.result.evaluations.length === 0 && eligibleRun?.status === 'failed';
      const binding = activeBinding(current);
      const verified = current.identity.role === 'oid_observer' && current.identity.transactionReadOnly === 'on' &&
        eligibleRun?.status === 'failed' && eligibleRun.terminal_reason === 'platform_failure_recovery_exhausted' &&
        eligibleRun.cancellation_reason === 'coordinator_platform_failure' && recoveryRow?.status === 'refunded' &&
        recoveryRow.clock_excluded_ms <= 180_000 && Date.parse(recoveryRow.deadline_at) === Date.parse(recoveryRow.started_at) + 180_000 &&
        SHA256.test(recoveryRow.payload_hash ?? '') && SHA256.test(recoveryRow.incident_evidence_hash ?? '') &&
        SHA256.test(recoveryRow.latest_evidence_hash ?? '') &&
        current.result.refunds.length === 1 && refundEntries.length === 1 &&
        amount.toString() === String(current.result.refunds[0]?.bonus_refunded_units) &&
        current.result.refunds[0]?.operation_id === 'runref_' + runId.replaceAll('-', '') &&
        current.result.refundAudits.length === 1 && current.result.refundAudits[0].operation_id === current.result.refunds[0].operation_id &&
        current.result.refundAudits[0].event_type === 'run_platform_failure_refunded' &&
        current.result.refundAudits[0].actor_owner_id === eligibleRun.owner_id &&
        current.result.refundAudits[0].subject_owner_id === eligibleRun.owner_id &&
        current.result.refundAudits[0].run_id === runId && current.result.refundAudits[0].evidence_hash === recoveryRow.latest_evidence_hash &&
        current.result.refundAudits[0].bonus_refunded_units === amount.toString() &&
        current.result.refundAudits[0].original_action_id === actionId && current.result.refundAudits[0].original_operation_id === recoveryRow.operation_id &&
        refundEvent.length === 1 && refundEvent[0].action_id === actionId &&
        refundEvent[0].operation_id === recoveryRow.operation_id &&
        refundEvent[0].evidence_hash === recoveryRow.latest_evidence_hash &&
        refundEvent[0].bonus_refunded_units === amount.toString() && refundEvent[0].cash_refunded_units === '0' &&
        sourceAction.length === 1 && ['observed', 'unknown'].includes(sourceAction[0].receipt_status) &&
        recoveryRow.action_id === actionId && recoveryRow.run_id === runId &&
        recoveryRow.owner_id === eligibleRun.owner_id && recoveryRow.agent_id === eligibleRun.agent_id &&
        recoveryRow.task_index === sourceAction[0].task_index && recoveryRow.operation_id === sourceAction[0].operation_id &&
        recoveryRow.payload_hash === sourceAction[0].payload_hash &&
        operation?.environmentId === recoveryRow.environment_id && operation?.generationId === binding.generationId &&
      operation?.idempotencyKeySha256 === hash(`task-action-${actionId}`) && operation.status === 'settled' &&
        operation.operationKind === sourceAction[0].action_kind &&
        /^0x[0-9a-f]{64}$/i.test(operation.transactionHash ?? '') && operation.responseSha256 === null &&
        recoverySourceBound(source) &&
        exactFence && finalizationConditions.verified && noGrade &&
        current.result.actions.length === 1 && current.result.actions[0].outbox_status === 'delivered' &&
        current.result.reservations.length === 1 && current.result.reservations.every((row) => row.source_kind === 'tester_bonus' && row.state === 'debited') &&
        current.result.ledger.filter((row) => row.entry_type === 'reserve' && row.source_kind === 'tester_bonus').length === 1 &&
        current.result.ledger.filter((row) => row.entry_type === 'debit' && row.source_kind === 'tester_bonus').length === 1 &&
        refundEntries.every((row) => row.source_kind === 'tester_bonus') &&
        current.result.reservations.every((row) => row.source_kind === 'tester_bonus') &&
        current.result.ledger.every((row) => row.source_kind === 'tester_bonus');
      return { verified, terminalReason: eligibleRun?.terminal_reason ?? null,
        runStatus: eligibleRun?.status ?? null, originalReceiptStatus: sourceAction[0]?.receipt_status ?? null,
        originalReceiptRemainsUnknown: originalReceiptRemainsUnknown === true, sourceOperationCount: source.result.length,
        sourceOperationStatus: operation?.status ?? null, sourceReceiptStatus: operation?.receiptStatus ?? null,
        sourceTransactionHashPresent: Boolean(operation?.transactionHash), originalActionCount: sourceAction.length,
        cashRefundedUnits: current.result.ledger.filter((row) => row.source_kind === 'cash_usdc' && row.entry_type === 'refund')
          .reduce((sum, row) => sum + BigInt(row.available_delta_units ?? 0), 0n).toString(),
        bonusRefundedUnits: amount.toString(), refundEntryCount: refundEntries.length,
        bonusReleaseEntryCount: releaseEntries.length, fenceVerified: exactFence,
        sourceOperationId: operation?.operationId ?? null, sourceResponseSha256: operation?.responseSha256 ?? null,
        actionEvidence, fenceEvidenceFiles,
        leaseSlotsReleased: current.result.slots.every((slot) => slot.released_at !== null),
        claimsReleased: current.result.claims.every((claim) => claim.released_at !== null),
        gradeRecorded: current.result.evaluations.length > 0,
        recoveryDeadlineAt: recoveryRow?.deadline_at ?? null, recoveryStartedAt: recoveryRow?.started_at ?? null,
        recoveryStatus: recoveryRow?.status ?? null, sourceActionStatus: action.receiptStatus,
        terminalFinalization: { elapsedMs: terminalFinalization.elapsedMs, conditions: terminalFinalization.conditions,
          failedConditions: terminalFinalization.failedConditions } };
    },
  };
  try {
    const output = await runGenuineS1OwnerCase({ ...commonCapture.genuineCaptureInput, captureId,
      mode: 'training', taskId: 'S1', automaticWorkerEvaluation: true, bonusCodeFunding: true,
      bddProbes: false, primaryClientOnly: false, platformRecoveryFault: recoveryFault });
    const genuineAttempt = await persistGenuineAttempt(commonCapture, 'exhausted', output);
    if (!(output.status === 'captured_platform_recovery_exhausted_without_grade' &&
      output.platformRecovery?.terminalCapturedWithoutGrade === true && UUID.test(output.runId))) {
      throw Object.assign(new Error('recovery_exhaustion_terminal_not_captured'), {
        code: 'RECOVERY_EXHAUSTION_RUN_INCOMPLETE', safeDiagnostic: { genuineAttempt,
          status: output.status, blocker: output.blocker ?? null, stages: output.stages?.slice(-8) ?? [] } });
    }
    target ??= { databaseName: commonCapture.databaseIsolation.databaseName,
      runId: output.runId, actionId: output.platformRecovery?.reconciledOriginalAction?.actionId };
    const owner = await readOwnerRecoverySnapshot(ownerPool, target);
    const postTerminalConditions = recoveryExhaustionTerminalConditions(owner);
    const binding = activeBinding(owner);
    const source = await readBefAction(befPool, { ...binding, participantId: binding.participantId });
    demand(owner.result.run?.status === 'failed' && owner.result.run.terminal_reason === 'platform_failure_recovery_exhausted' &&
      owner.result.recovery?.status === 'refunded' && owner.result.refunds.length === 1 &&
      postTerminalConditions.verified &&
      owner.result.evaluations.length === 0 && source.result.length === 1 && source.result[0].status === 'settled' &&
      source.result[0].generationStatus === 'fenced' && /^0x[0-9a-f]{64}$/i.test(source.result[0].transactionHash ?? '') &&
      source.result[0].responseSha256 === null && recoverySourceBound(source),
    'recovery_exhaustion_poststate_invalid');
    const proxy = recoveryFaultProxy.snapshot();
    const observerFault = recoveryObserverProxy.snapshot();
    const actionSubmissions = proxy.submissions.filter((row) => row.actionId === binding.actionId);
    demand(proxy.fault?.actionId === binding.actionId && proxy.fault.upstreamResponseComplete === true &&
      proxy.fault.downstreamResponseDelivered === false && observerFault.intervals.length === 1 &&
      actionSubmissions.length === 1 && actionSubmissions[0]?.count === 1 &&
      observerFault.intervals[0].endedAt && Date.parse(observerFault.intervals[0].endedAt) - Date.parse(observerFault.intervals[0].startedAt) >= RECOVERY_WINDOW_MS,
    'recovery_exhaustion_fault_window_not_proven');
    return { schemaVersion: 'bpc-platform-recovery-case/v1', captureId, genuineAttempt, status: 'verified_local_exhaustion',
      boundary: 'real_owner_ui_committed_bef_action_observer_outage_through_database_recovery_deadline_then_late_reconciliation',
      genuineRun: compactGenuine(output), action: { actionId: binding.actionId, ownerOperationId: binding.operationId,
        taskIndex: owner.result.actions[0].task_index, actionSequence: owner.result.actions[0].action_sequence,
        kind: owner.result.actions[0].action_kind, payloadHash: owner.result.actions[0].payload_hash,
        initialReceiptStatus: 'unknown', finalReceiptStatus: owner.result.actions[0].receipt_status,
        originalActionCount: owner.result.actions.length, outboxStatus: owner.result.actions[0].outbox_status,
        upstreamSubmissionCount: actionSubmissions.find((row) => row.actionId === binding.actionId)?.count ?? null },
      binding: { runId: target.runId, ownerId: owner.result.run.owner_id, agentId: owner.result.run.agent_id,
        mode: owner.result.run.mode, taskId: owner.result.tasks[0]?.task_id,
        environmentId: binding.environmentId, preparationId: binding.preparationId, generationId: binding.generationId,
        participantIdSha256: hash(binding.participantId), leaseId: binding.leaseId },
      recovery: { row: owner.result.recovery, observations: owner.result.recoveryObservations,
        restartReceipt, deadlineObservation, sourceOperationCount: source.result.length,
        originalEffectsPreserved: true, runOutcomeUnknownNotReopened: owner.result.evaluations.length === 0 },
      sourceOperation: source, proxy, observerFault,
      terminalEvidence: { actionEvidence: output.platformRecovery?.exhaustion?.actionEvidence,
        fenceEvidenceFiles: output.platformRecovery?.exhaustion?.fenceEvidenceFiles },
      finalState: { observerIdentity: owner.identity, run: owner.result.run,
        actions: owner.result.actions, tasks: owner.result.tasks.map((row) => ({ taskIndex: row.task_index,
          taskId: row.task_id, status: row.status, closureStatus: row.closure_status,
          closureReason: row.closure_reason })), evaluations: owner.result.evaluations,
        claims: owner.result.claims, slots: owner.result.slots, reservations: owner.result.reservations,
        refunds: owner.result.refunds, refundAudits: owner.result.refundAudits,
        ledger: owner.result.ledger, holds: owner.result.holds,
        terminalEvents: owner.result.terminalEvents } };
  } finally {
    if (!unblocked && recoveryObserverProxy.snapshot().blocked) recoveryObserverProxy.unblock();
    if (proxyArmed) {
      const proxy = recoveryFaultProxy.snapshot();
      if (proxy.fault && !proxy.armed) recoveryFaultProxy.resetAfterIncident();
    }
    await ownerPool.end();
    await befPool.end();
  }
}

export async function observeBefRecoveryOperations(cases) {
  const pool = await makeBefObserverPool();
  try {
    const observed = await readonly(pool, async (client) => {
      const entries = [];
      for (const [caseName, value] of Object.entries(cases)) {
        const { binding, action } = value;
        demand(UUID.test(binding?.generationId ?? '') && UUID.test(action?.actionId ?? '') &&
          /^[A-Za-z0-9._-]{1,64}$/.test(binding?.environmentId ?? ''), 'restore_bef_binding_invalid');
        const keyHash = hash(`task-action-${action.actionId}`);
        const result = (await client.query(`SELECT o.operation_id::text,o.env_id,o.generation_id::text,
            o.participant_id,o.idempotency_key_sha256,o.request_sha256,o.operation_kind,o.status,
            o.transaction_hash,o.receipt_status,o.response_sha256,g.status AS generation_status
          FROM bef_operation o JOIN bef_generation g USING(env_id,generation_id)
          WHERE o.env_id=$1 AND o.generation_id=$2::uuid AND o.idempotency_key_sha256=$3`,
        [binding.environmentId, binding.generationId, keyHash])).rows;
        entries.push({ caseName, actionId: action.actionId, operations: result.map((row) => ({
          operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
          participantIdSha256: hash(row.participant_id), idempotencyKeySha256: row.idempotency_key_sha256,
          requestSha256: row.request_sha256, operationKind: row.operation_kind, status: row.status,
          transactionHash: row.transaction_hash, receiptStatus: row.receipt_status,
          responseSha256: row.response_sha256, generationStatus: row.generation_status,
        })) });
      }
      return entries;
    }, 'bef', 'bef_observer');
    return { schemaVersion: 'bpc-restored-bef-operation-observation/v1', ...observed };
  } finally { await pool.end(); }
}

export async function runBetaRecoveryCases({ commonCapture, recoveryFaultProxy, recoveryObserverProxy, progress: progressFn,
  onGenuineRunCompleted }) {
  demand(commonCapture?.databaseIsolation?.databaseName && /^oid_acceptance_[a-f0-9]{32}$/.test(commonCapture.databaseIsolation.databaseName),
    'recovery_requires_unique_acceptance_database');
  demand(recoveryFaultProxy && typeof recoveryFaultProxy.arm === 'function' &&
    typeof recoveryFaultProxy.resetAfterIncident === 'function' && recoveryObserverProxy &&
    typeof recoveryObserverProxy.block === 'function' && typeof recoveryObserverProxy.unblock === 'function',
  'recovery_proxies_missing');
  await progress(progressFn, { phase: 'recovery_capture_started', databaseName: commonCapture.databaseIsolation.databaseName });
  const recovered = await runRecoveredCommittedAction(commonCapture, recoveryFaultProxy, progressFn,
    { taskId: 'S1', onGenuineRunCompleted });
  await progress(progressFn, { phase: 'recovery_committed_action_verified', runId: recovered.binding.runId,
    actionId: recovered.action.actionId });
  const exhausted = await runExhaustedCommittedAction(commonCapture, recoveryFaultProxy, recoveryObserverProxy, progressFn);
  const coreResult = { schemaVersion: 'bpc-platform-recovery-runtime-observation/v1', scenarioId: 'BPC-SC-017', status: 'verified',
    boundary: 'isolated_local_owner_browser_api_postgres_bef_observer_and_real_loopback_fault_proxies',
    localStatus: 'observed_partial', database: { name: commonCapture.databaseIsolation.databaseName,
      uniquePerCapture: true, retainedForInspection: true },
    cases: { committedActionRecovery: recovered, recoveryDeadlineExhaustion: exhausted },
    claims: { sourceOperationResubmitted: false, publicRecoveryAuthorityProvided: false,
      productReleaseActivation: false, targetHostAcceptance: 'not_run', actualExternalClient: false },
    unproven: ['owner_cancel_start_order_race', 'revoke_after_start', 'stale_callback_race',
      'forged_platform_failure_authority_negative', 'target_host_recovery_authority'] };
  // Preserve the independently replayable recovery boundary before later report
  // and backup work, so a later restore failure cannot erase this raw evidence.
  const inputHashesAfter = {};
  for (const [path, expectedHash] of Object.entries(commonCapture.sourceInputsBefore)) {
    const verified = await verifyEvidenceReference(commonCapture.repoRoot, { path, sha256: expectedHash }, 'recovery_source_stability');
    inputHashesAfter[path] = verified.sha256;
  }
  const directory = resolve(commonCapture.repoRoot, 'artifacts/runs/beta-platform-recovery-stage', commonCapture.runId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stageCapture = { schemaVersion: 'beta-platform-recovery-capture/v1', captureId: commonCapture.runId,
    boundary: 'isolated_local_browser_backend_postgres_bef_files', result: coreResult,
    provenance: { databaseIsolation: commonCapture.databaseIsolation, inputHashesBefore: commonCapture.sourceInputsBefore,
      inputHashesAfter, sourceStableDuringRun: true }, targetHostAcceptance: 'blocked_target_not_selected' };
  assertSecretFree(stageCapture, 'recovery-stage-capture');
  const stageBytes = Buffer.from(`${JSON.stringify(stageCapture, null, 2)}\n`);
  await writeFile(resolve(directory, 'capture.json'), stageBytes, { flag: 'wx', mode: 0o600 });
  await progress(progressFn, { phase: 'recovery_stage_capture_saved', captureId: commonCapture.runId,
    path: relative(commonCapture.repoRoot, resolve(directory, 'capture.json')).split(sep).join('/'), sha256: hash(stageBytes) });
  await progress(progressFn, { phase: 'recovery_collector_case_started', taskId: 'S4' });
  const collectorS4 = await runRecoveredCommittedAction(commonCapture, recoveryFaultProxy, progressFn,
    { taskId: 'S4', requirePassingEvaluation: true });
  await progress(progressFn, { phase: 'recovery_collector_case_verified', taskId: 'S4',
    runId: collectorS4.binding.runId, actionId: collectorS4.action.actionId });
  await progress(progressFn, { phase: 'recovery_collector_case_started', taskId: 'M3' });
  const collectorM3 = await runRecoveredCommittedAction(commonCapture, recoveryFaultProxy, progressFn,
    { taskId: 'M3', requirePassingEvaluation: true });
  await progress(progressFn, { phase: 'recovery_collector_case_verified', taskId: 'M3',
    runId: collectorM3.binding.runId, actionId: collectorM3.action.actionId });
  return { ...coreResult, collectorCases: { S4: collectorS4, M3: collectorM3 } };
}
