import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, lstat } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import pg from 'pg';
import { assertSecretFree } from './evidence.mjs';
import { observeBefRecoveryOperations, runBetaRecoveryCases } from './beta-recovery-cases.mjs';
import { runGenuineS1OwnerCase } from './genuine-s1-cases.mjs';

const { Pool } = pg;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const REQUIRED_SOURCE_TABLES = ['oid_benchmark_run', 'oid_run_operation', 'oid_ledger_operation',
  'oid_bonus_code_claim_operation', 'oid_task_preparation_generation', 'oid_support_report',
  'oid_support_report_audit', 'oid_support_image_upload', 'oid_support_report_deletion_receipt',
  'oid_support_upload_gc_receipt', 'oid_support_report_rate'];
const delay = (ms) => new Promise((done) => setTimeout(done, ms));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function demand(condition, code) {
  if (!condition) throw Object.assign(new Error(code), { code });
}

const SAFE_BLOCKER_CODE = /^[a-z0-9_]{1,80}$/;
const EXPECTED_BLOCKER_STATUS = 'captured_s1_training_run_completed_by_server_worker';
const SAFE_CALLBACK_STAGE = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_CALLBACK_METADATA = /^[A-Za-z0-9_]{1,96}$/;
const SAFE_CALLBACK_FRAME = /^\/workspace\/[A-Za-z0-9._/-]{1,320}:\d+:\d+$/;

function callbackStackFrames(stack) {
  if (typeof stack !== 'string') return [];
  const frames = [];
  for (const line of stack.split(/\r?\n/).slice(1, 80)) {
    const match = /(?:file:\/\/)?(\/workspace\/[A-Za-z0-9._/-]{1,320}:\d+:\d+)/.exec(line);
    if (match && SAFE_CALLBACK_FRAME.test(match[1])) frames.push(match[1]);
    if (frames.length === 5) break;
  }
  return frames;
}

export function wrapCombinedCallbackError(error, stage) {
  demand(SAFE_CALLBACK_STAGE.test(stage ?? ''), 'combined_callback_stage_invalid');
  const rawName = typeof error?.name === 'string' ? error.name
    : typeof error?.constructor?.name === 'string' ? error.constructor.name : 'Error';
  const errorName = /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(rawName) ? rawName : 'Error';
  const rawCode = error?.code === undefined || error?.code === null ? '' : String(error.code);
  const errorCode = SAFE_CALLBACK_METADATA.test(rawCode) ? rawCode : 'callback_stage_failed';
  const safeDiagnostic = { schemaVersion: 'beta-combined-callback-diagnostic/v1', stage, errorName,
    errorCode: rawCode && SAFE_CALLBACK_METADATA.test(rawCode) ? rawCode : null,
    topStackFrames: callbackStackFrames(error?.stack) };
  const wrapped = new Error(errorCode);
  wrapped.code = errorCode;
  wrapped.safeDiagnostic = safeDiagnostic;
  return wrapped;
}

export async function runCombinedCallbackDiagnosticScope(callback) {
  let stage = 'callback_start';
  try {
    return await callback((nextStage) => {
      demand(SAFE_CALLBACK_STAGE.test(nextStage ?? ''), 'combined_callback_stage_invalid');
      stage = nextStage;
    });
  } catch (error) {
    throw wrapCombinedCallbackError(error, stage);
  }
}

function validatedCallbackDiagnostic(value) {
  if (!value || value.schemaVersion !== 'beta-combined-callback-diagnostic/v1' ||
      !SAFE_CALLBACK_STAGE.test(value.stage ?? '') ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value.errorName ?? '') ||
      !(value.errorCode === null || SAFE_CALLBACK_METADATA.test(value.errorCode ?? '')) ||
      !Array.isArray(value.topStackFrames) || value.topStackFrames.length > 5 ||
      value.topStackFrames.some((frame) => !SAFE_CALLBACK_FRAME.test(frame))) return null;
  return { schemaVersion: value.schemaVersion, stage: value.stage, errorName: value.errorName,
    errorCode: value.errorCode, topStackFrames: [...value.topStackFrames] };
}

export function combinedBlockerError(output) {
  const code = combinedBlockerFailureCode(output);
  if (!code) return null;
  const error = new Error(code);
  error.code = code;
  const diagnostic = validatedCallbackDiagnostic(output?.safeDiagnostic);
  if (diagnostic) error.safeDiagnostic = diagnostic;
  return error;
}

export function combinedBlockerFailureCode(output) {
  if (output?.status === EXPECTED_BLOCKER_STATUS) return null;
  const stage = typeof output?.blocker?.stage === 'string' && SAFE_BLOCKER_CODE.test(output.blocker.stage)
    ? output.blocker.stage : 'unknown_stage';
  const reason = typeof output?.blocker?.reasonCode === 'string' && SAFE_BLOCKER_CODE.test(output.blocker.reasonCode)
    ? output.blocker.reasonCode : 'unknown_reason';
  return `combined_active_blocker_${stage}_${reason}`;
}

export function agentAcceptanceResponseSummary({ response, intentId, operationId, replayed }) {
  demand(typeof response?.status === 'function' && UUID.test(intentId ?? '') && UUID.test(operationId ?? ''),
    'combined_agent_acceptance_response_shape_invalid');
  return { method: 'POST', path: `/api/agent/run-intents/${intentId}/accept`, status: response.status(),
    operationId, replayed: replayed === true };
}

export function exactKnownPassingEvaluation(value) {
  return value?.outcomeStatus === 'known' && value?.outcome === 'passed' &&
    value?.credit?.numerator === '1' && value?.credit?.denominator === '1' &&
    value?.mandatoryViolationPresent === false;
}

export function pauseAuditActorsMatch({ adminOwnerId, control, event }) {
  return UUID.test(adminOwnerId ?? '') && control?.changed_by_owner_id === adminOwnerId &&
    event?.actor_owner_id === adminOwnerId;
}

export function exactBonusRedemptionRequestCapture({ listenerError, requestCount, payload }) {
  return !listenerError && requestCount === 1 && payload &&
    Object.keys(payload).sort().join(',') === 'code,operationId' &&
    typeof payload.code === 'string' && /^BPC-[A-Za-z0-9_-]{43}$/.test(payload.code) &&
    typeof payload.operationId === 'string' && UUID.test(payload.operationId);
}

export function quoteUnits(value) {
  demand(typeof value === 'string', 'combined_quote_display_missing');
  const match = /(?:^|\s)([0-9]+(?:\.[0-9]{1,6})?)\s+USDC\.?(?:\s|$)/i.exec(value);
  demand(match, 'combined_quote_display_invalid');
  const [whole, fraction = ''] = match[1].split('.');
  return BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, '0') || '0');
}

function formatUnits(value) {
  const units = typeof value === 'bigint' ? value : BigInt(value);
  demand(units >= 0n, 'combined_quote_units_invalid');
  return `${units / 1_000_000n}.${(units % 1_000_000n).toString().padStart(6, '0')}`;
}

function withDatabase(urlValue, databaseName) {
  const url = new URL(urlValue);
  url.pathname = `/${databaseName}`;
  return url.href;
}

function rows(result) {
  demand(Array.isArray(result?.rows), 'combined_observer_rows_invalid');
  return result.rows;
}

async function readonly(pool, databaseName, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = rows(await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS read_only,clock_timestamp() AS database_now`))[0];
    demand(identity?.role === 'oid_observer' && identity.read_only === 'on' && identity.database_name === databaseName,
      'combined_observer_identity_invalid');
    const value = await callback(client);
    await client.query('COMMIT');
    return { identity: { role: identity.role, databaseName: identity.database_name,
      transactionReadOnly: identity.read_only, databaseNow: new Date(identity.database_now).toISOString() }, value };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function readQueueSnapshot(pool, databaseName, runId) {
  return readonly(pool, databaseName, async (client) => {
    const run = rows(await client.query(`SELECT r.id::text,r.intent_id::text,r.owner_id::text,r.agent_id::text,r.mode,
        r.task_ids,r.status,r.started_at::text,r.finished_at::text,r.queue_deadline::text,r.quote_price_units::text,
        i.status AS intent_status,i.operation_id AS accept_operation_id,i.manifest_hash
      FROM oid_benchmark_run r JOIN oid_run_launch_intent i ON i.id=r.intent_id WHERE r.id=$1::uuid`, [runId]));
    const tasks = rows(await client.query(`SELECT task_index,task_id,status,started_at::text,finished_at::text,
        closure_status,closure_reason FROM oid_run_task WHERE run_id=$1::uuid ORDER BY task_index`, [runId]));
    const slots = rows(await client.query(`SELECT run_id::text,agent_id::text,claim_id::text,state,acquired_at::text,released_at::text
      FROM oid_run_execution_slot WHERE run_id=$1::uuid ORDER BY acquired_at`, [runId]));
    const claims = rows(await client.query(`SELECT claim_id::text,status,turn_number::text,claimed_at::text,released_at::text
      FROM oid_run_dispatch_claim WHERE run_id=$1::uuid ORDER BY claimed_at`, [runId]));
    const outbox = rows(await client.query(`SELECT event_type,status,created_at::text,delivered_at::text
      FROM oid_run_outbox WHERE run_id=$1::uuid ORDER BY created_at,event_type`, [runId]));
    const reservations = rows(await client.query(`SELECT id::text,source_kind,bonus_grant_id::text,amount_units::text,state
      FROM oid_run_reservation WHERE run_id=$1::uuid ORDER BY id`, [runId]));
    const hold = rows(await client.query(`SELECT run_id::text,mode,amount_units::text,state,utc_day
      FROM oid_run_budget_hold WHERE run_id=$1::uuid`, [runId]));
    const events = rows(await client.query(`SELECT sequence::text,source,event_type,payload_hash,created_at::text
      FROM oid_run_event WHERE run_id=$1::uuid ORDER BY sequence`, [runId]));
    return { run: run[0] ?? null, tasks, slots, claims, outbox, reservations, hold, events };
  });
}

async function readOperationsControl(pool, databaseName, operationId = null) {
  return readonly(pool, databaseName, async (client) => {
    const control = rows(await client.query(`SELECT mode,revision::text,changed_at::text,changed_by_owner_id::text,
        reason_code,operation_id FROM oid_beta_operations_control WHERE id=1`))[0] ?? null;
    const events = operationId ? rows(await client.query(`SELECT operation_id,actor_owner_id::text,revision::text,
        previous_mode,next_mode,reason_code,payload_hash,created_at::text
      FROM oid_beta_operations_control_event WHERE operation_id=$1 ORDER BY revision`, [operationId])) : [];
    return { control, events };
  });
}

async function createAndAcceptQueuedS1({ commonCapture, agentId, bearer, ownerPage, observerPool }) {
  demand(UUID.test(agentId ?? '') && typeof bearer === 'string' && bearer.length >= 32,
    'combined_queue_agent_context_missing');
  await ownerPage.goto(`/runs?agentId=${encodeURIComponent(agentId)}`, { waitUntil: 'domcontentloaded' });
  await ownerPage.getByTestId('run-intent-form').waitFor({ state: 'visible', timeout: 20_000 });
  await ownerPage.getByTestId('run-agent-select').selectOption(agentId);
  await ownerPage.getByTestId('run-mode-select').selectOption('training');
  const catalogResponse = await ownerPage.request.get(new URL('/api/owner/runs/catalog', commonCapture.publicOrigin).toString());
  const catalog = await catalogResponse.json().catch(() => ({}));
  demand(catalogResponse.status() === 200 && catalog?.intentCreationReady === true &&
    catalog?.activeRelease?.openTaskIds?.includes('S1'), 'combined_queue_release_not_available');
  for (const taskId of catalog.activeRelease.openTaskIds) {
    const control = ownerPage.getByTestId(`run-task-checkbox-${taskId}`);
    if (taskId === 'S1' && !await control.isChecked()) await control.check();
    if (taskId !== 'S1' && await control.isChecked()) await control.uncheck();
  }
  demand(await ownerPage.locator('[data-testid^="run-task-checkbox-"]:checked').count() === 1,
    'combined_queue_task_selection_invalid');
  await ownerPage.getByTestId('run-cash-ceiling').fill('0');
  const quoteText = (await ownerPage.getByTestId('run-selected-quote').innerText()).trim();
  const expectedQuote = formatUnits(quoteUnits(quoteText));
  const intentResponsePromise = ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/owner/runs/intents' && response.request().method() === 'POST', { timeout: 20_000 });
  commonCapture.ownerCapture?.action?.('click', 'combined-restore-queued-run-intent-create');
  await ownerPage.getByTestId('run-intent-create').click();
  const intentResponse = await intentResponsePromise;
  const intentRequest = intentResponse.request().postDataJSON();
  const intentBody = await intentResponse.json().catch(() => ({}));
  const intentId = intentBody?.intent?.id;
  demand([200, 201].includes(intentResponse.status()) && UUID.test(intentId ?? '') &&
    intentRequest?.agentId === agentId && intentRequest?.mode === 'training' &&
    JSON.stringify(intentRequest?.taskIds) === JSON.stringify(['S1']) &&
    /^0(?:\.0{1,6})?$/.test(intentRequest?.cashCeiling ?? '') &&
    quoteUnits(intentRequest.expectedQuotePrice + ' USDC') === quoteUnits(expectedQuote + ' USDC') &&
    intentRequest.expectedReleaseIdentity === catalog.activeRelease.releaseIdentity &&
    intentRequest.expectedManifestHash === catalog.activeRelease.manifestHash,
  'combined_queue_intent_ui_receipt_invalid');
  const acceptOperationId = randomUUID();
  const acceptResponse = await ownerPage.request.post(new URL(`/api/agent/run-intents/${intentId}/accept`, commonCapture.publicOrigin).toString(), {
    headers: { authorization: `Bearer ${bearer}`, origin: commonCapture.publicOrigin, 'content-type': 'application/json' },
    data: { operationId: acceptOperationId },
  });
  const acceptBody = await acceptResponse.json().catch(() => ({}));
  const runId = acceptBody?.run?.id ?? acceptBody?.run?.runId;
  demand([200, 201].includes(acceptResponse.status()) && UUID.test(runId ?? '') &&
    ['queued', 'preparing', 'running'].includes(acceptBody?.run?.status), 'combined_queue_agent_accept_failed');
  const accepted = await readQueueSnapshot(observerPool, commonCapture.databaseIsolation.databaseName, runId);
  demand(accepted.value.run?.intent_id === intentId && accepted.value.run.owner_id === commonCapture.ownerId &&
    accepted.value.run.agent_id === agentId && accepted.value.run.status === 'queued' && accepted.value.run.started_at === null &&
    accepted.value.run.intent_status === 'accepted' && accepted.value.tasks.length === 1 &&
    accepted.value.tasks[0].task_id === 'S1' && accepted.value.tasks[0].status === 'queued' &&
    accepted.value.tasks[0].started_at === null && accepted.value.slots.length === 0 && accepted.value.claims.length === 0,
  'combined_queue_acceptance_not_durably_queued');
  return { intentId, createOperationId: intentRequest.operationId, acceptOperationId, runId,
    agentId, taskIds: ['S1'], expectedQuote: expectedQuote, cashCeiling: '0',
    intentCreatePayload: structuredClone(intentRequest),
    ownerUi: { createIntentMethod: intentResponse.request().method(), createIntentPath: new URL(intentResponse.url()).pathname,
      createIntentStatus: intentResponse.status(), createIntentOperationId: intentRequest.operationId },
    agentAcceptance: agentAcceptanceResponseSummary({ response: acceptResponse, intentId,
      operationId: acceptOperationId, replayed: acceptBody.replayed === true }),
    acceptedBeforePause: accepted };
}

async function pauseAdmissionsFromAdminUi({ commonCapture, observerPool }) {
  const { adminPage, adminOwnerId, publicOrigin, databaseIsolation } = commonCapture;
  demand(UUID.test(adminOwnerId ?? ''), 'combined_pause_admin_actor_context_missing');
  const before = await readOperationsControl(observerPool, databaseIsolation.databaseName);
  demand(before.value.control?.mode === 'active', 'combined_pause_precondition_not_active');
  await adminPage.goto(new URL('/admin/operations', publicOrigin).toString(), { waitUntil: 'domcontentloaded' });
  await adminPage.getByTestId('operations-pause').waitFor({ state: 'visible', timeout: 20_000 });
  demand((await adminPage.getByTestId('operations-mode').innerText()).includes('Starts active'),
    'combined_pause_admin_ui_not_active');
  const responsePromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/admin/operations/control' && response.request().method() === 'POST',
  { timeout: 20_000 });
  commonCapture.adminCapture?.action?.('click', 'combined-restore-pause-admissions');
  await adminPage.getByTestId('operations-pause').click();
  const response = await responsePromise;
  const payload = await response.json().catch(() => ({}));
  const request = response.request().postDataJSON();
  demand([200, 201].includes(response.status()) && payload?.control?.mode === 'paused' &&
    request?.mode === 'paused' && request?.reasonCode === 'maintenance' && UUID.test(request?.operationId ?? ''),
  'combined_pause_ui_update_not_confirmed');
  await adminPage.getByTestId('operations-mode').getByText('Starts paused').waitFor({ state: 'visible', timeout: 15_000 });
  const after = await readOperationsControl(observerPool, databaseIsolation.databaseName, request.operationId);
  const event = after.value.events[0];
  demand(after.value.control?.mode === 'paused' && Number(after.value.control.revision) === Number(before.value.control.revision) + 1 &&
    pauseAuditActorsMatch({ adminOwnerId, control: after.value.control, event }) &&
    after.value.control.operation_id === request.operationId && event?.operation_id === request.operationId && event.previous_mode === 'active' &&
    event.next_mode === 'paused' && event.reason_code === 'maintenance' && HASH.test(event.payload_hash ?? ''),
  'combined_pause_durable_audit_mismatch');
  return { before: before.value, after: after.value, ui: { method: response.request().method(),
    path: new URL(response.url()).pathname, status: response.status(), operationId: request.operationId,
    modeText: await adminPage.getByTestId('operations-mode').innerText() } };
}

async function verifyQueuedRunStayedPaused(pool, commonCapture, runId, pauseOperationId) {
  let prior;
  let stableSamples = 0;
  const deadline = Date.now() + 7_000;
  let final;
  while (Date.now() < deadline && stableSamples < 4) {
    final = await readQueueSnapshot(pool, commonCapture.databaseIsolation.databaseName, runId);
    const control = await readOperationsControl(pool, commonCapture.databaseIsolation.databaseName, pauseOperationId);
    demand(control.value.control?.mode === 'paused' && control.value.control.operation_id === pauseOperationId,
      'combined_pause_control_did_not_persist');
    demand(final.value.run?.status === 'queued' && final.value.run.started_at === null &&
      final.value.tasks.length === 1 && final.value.tasks[0].status === 'queued' && final.value.tasks[0].started_at === null &&
      final.value.slots.length === 0 && final.value.claims.length === 0 &&
      !final.value.outbox.some((row) => ['run.started', 'task.started'].includes(row.event_type)),
    'combined_paused_queued_run_started_or_claimed');
    const serialized = JSON.stringify(final.value);
    stableSamples = serialized === prior ? stableSamples + 1 : 0;
    prior = serialized;
    if (stableSamples < 4) await delay(350);
  }
  demand(stableSamples >= 4 && final?.identity?.role === 'oid_observer' && final.identity.transactionReadOnly === 'on',
    'combined_paused_queue_not_stable');
  return final;
}

async function runActiveBlockerWithQueuedPausedRun({ commonCapture, observerPool, progressFn }) {
  let queue = null;
  let paused = null;
  let activeBeforeDrain = null;
  let redemptionPayload = null;
  let redemptionRequestCount = 0;
  let redemptionListenerError = null;
  const ownerPage = commonCapture.ownerPage;
  const requestListener = (request) => {
    if (request.method() !== 'POST' || new URL(request.url()).pathname !== '/api/owner/bonus-codes/redeem') return;
    redemptionRequestCount += 1;
    if (redemptionRequestCount !== 1) return;
    try { redemptionPayload = request.postDataJSON(); }
    catch { redemptionListenerError = 'bonus_redemption_request_body_invalid'; }
  };
  ownerPage.on('request', requestListener);
  let blockerOutput;
  let retryMaterial;
  try {
    blockerOutput = await runGenuineS1OwnerCase({ ...commonCapture.genuineCaptureInput,
      captureId: randomUUID(), mode: 'training', taskId: 'S1', automaticWorkerEvaluation: true,
      bonusCodeFunding: true, bddProbes: false, primaryClientOnly: false,
      onGenuineFirstTaskActive: async (active) => {
        await runCombinedCallbackDiagnosticScope(async (setStage) => {
          setStage('active_callback_preconditions');
          demand(!queue && !paused && UUID.test(active.runId ?? '') && active.ownerId === commonCapture.ownerId &&
            UUID.test(active.agentId ?? '') && typeof active.agentBearer === 'string' && active.agentBearer.length >= 32 &&
            UUID.test(active.intentId ?? '') && typeof active.createIntentOperationId === 'string' &&
            typeof active.acceptOperationId === 'string' && active.intentCreatePayload?.operationId === active.createIntentOperationId,
          'combined_active_blocker_callback_invalid');
          setStage('active_blocker_observer_snapshot');
          activeBeforeDrain = await readQueueSnapshot(observerPool, commonCapture.databaseIsolation.databaseName, active.runId);
          setStage('active_blocker_snapshot_validation');
          demand(activeBeforeDrain.value.run?.owner_id === commonCapture.ownerId &&
            activeBeforeDrain.value.run?.agent_id === active.agentId && activeBeforeDrain.value.run?.status === 'running' &&
            activeBeforeDrain.value.run?.started_at !== null && activeBeforeDrain.value.tasks.length === 1 &&
            activeBeforeDrain.value.tasks[0].status === 'active' && activeBeforeDrain.value.slots.length === 1 &&
            activeBeforeDrain.value.slots[0].state === 'running' && activeBeforeDrain.value.claims.length === 1 &&
            activeBeforeDrain.value.claims[0].status === 'claimed',
          'combined_pause_blocker_not_holding_live_slot');
          setStage('queue_create_accept_and_observer_snapshot');
          await progressFn?.({ component: 'beta_combined_restore', phase: 'queue_accept_while_blocker_active', runId: active.runId });
          queue = await createAndAcceptQueuedS1({ commonCapture, agentId: active.agentId,
            bearer: active.agentBearer, ownerPage, observerPool });
          setStage('queue_pre_pause_durable_validation');
          demand(queue.agentId === active.agentId && queue.acceptedBeforePause.value.run?.status === 'queued' &&
            queue.acceptedBeforePause.value.slots.length === 0 && queue.acceptedBeforePause.value.claims.length === 0,
          'combined_second_same_agent_run_not_queued_behind_active_blocker');
          setStage('admin_pause_ui_and_durable_audit');
          paused = await pauseAdmissionsFromAdminUi({ commonCapture, observerPool });
          setStage('admin_pause_result_validation');
          demand(paused.after.control.mode === 'paused', 'combined_operations_pause_not_persisted');
          setStage('retry_material_capture');
          retryMaterial = { blocker: { runId: active.runId, agentId: active.agentId, agentBearer: active.agentBearer,
            intentId: active.intentId, createIntentOperationId: active.createIntentOperationId,
            acceptOperationId: active.acceptOperationId,
            intentCreatePayload: structuredClone(active.intentCreatePayload) },
            queue: { runId: queue.runId, intentId: queue.intentId, createIntentOperationId: queue.createOperationId,
              acceptOperationId: queue.acceptOperationId, intentCreatePayload: structuredClone(queue.intentCreatePayload) } };
        });
      },
    });
  } finally {
    ownerPage.off('request', requestListener);
  }
  const blockerError = combinedBlockerError(blockerOutput);
  if (blockerError) throw blockerError;
  demand(exactBonusRedemptionRequestCapture({ listenerError: redemptionListenerError,
    requestCount: redemptionRequestCount, payload: redemptionPayload }),
  'combined_bonus_redemption_ram_capture_invalid');
  demand(blockerOutput?.status === 'captured_s1_training_run_completed_by_server_worker' && blockerOutput.trainingRunCompletion?.status === 'verified' &&
    blockerOutput.taskGradePublished === false && blockerOutput.bonusFunding?.redemption?.status === 200 &&
    blockerOutput.bonusFunding?.redemption?.redemptionId && blockerOutput.bonusFunding?.redemption?.grantId &&
    retryMaterial?.blocker?.runId === blockerOutput.run?.runId &&
    retryMaterial.blocker.createIntentOperationId === blockerOutput.launchIntent?.operationId &&
    retryMaterial.blocker.acceptOperationId === blockerOutput.run?.acceptOperationId,
  'combined_active_blocker_worker_completion_invalid');
  const workerRun = await runBetaRecoveryCasesCompletedRunState(observerPool, commonCapture, blockerOutput.run.runId);
  demand(workerRun.status === 'completed' && workerRun.evaluations.length === 1 &&
    exactKnownPassingEvaluation(workerRun.evaluations[0]),
  'combined_active_worker_run_did_not_drain_under_pause');
  const pausedQueue = await verifyQueuedRunStayedPaused(observerPool, commonCapture, queue.runId, paused.after.control.operation_id);
  const bonus = blockerOutput.bonusFunding;
  demand(redemptionPayload.operationId === bonus.redemption.operationId &&
    UUID.test(bonus.redemption.redemptionId ?? '') && UUID.test(bonus.redemption.grantId ?? '') &&
    bonus.redemption.redemptionId === blockerOutput.bonusFunding.redemption.redemptionId,
  'combined_bonus_redemption_not_bound_to_real_ui_receipt');
  retryMaterial.redemptionPayload = redemptionPayload;
  retryMaterial.redemption = { operationId: bonus.redemption.operationId, redemptionId: bonus.redemption.redemptionId,
    grantId: bonus.redemption.grantId, codeId: bonus.issue.codeId, amountUnits: bonus.amountUnits };
  return { capture: { schemaVersion: 'bpc-combined-active-blocker-queue/v1', blockerRun: {
      runId: blockerOutput.run.runId, ownerId: blockerOutput.ownerId, agentId: blockerOutput.agent.agentId,
      status: blockerOutput.status, taskIds: blockerOutput.taskIds, intentId: blockerOutput.launchIntent.intentId,
      createIntentOperationIdSha256: sha256(Buffer.from(blockerOutput.launchIntent.operationId)),
      acceptOperationIdSha256: sha256(Buffer.from(blockerOutput.run.acceptOperationId)),
      quoteUnits: blockerOutput.launchIntent.quotePriceUnits, releaseIdentity: blockerOutput.release.releaseIdentity,
      manifestHash: blockerOutput.release.manifestHash, taskEvaluation: workerRun.evaluations,
      bonusFunding: { codeId: bonus.issue.codeId, redemptionId: bonus.redemption.redemptionId,
        grantId: bonus.redemption.grantId, redemptionOperationIdSha256: sha256(Buffer.from(bonus.redemption.operationId)),
        amountUnits: bonus.amountUnits, sourceKind: 'tester_bonus',
        workerRunFunding: bonus.workerRunFunding } }, activeBeforeQueue: activeBeforeDrain,
      queue, pause: paused, activeRunDrain: workerRun, queuedAfterDrain: pausedQueue }, retryMaterial };
}

async function writeEvidenceFile(root, relativePath, value) {
  const path = resolve(root, ...relativePath.split('/'));
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await import('node:fs/promises').then(({ writeFile }) => writeFile(path, bytes, { flag: 'wx', mode: 0o600 }));
  return { relativePath, sourcePath: relativePath, role: 'local_acceptance_observation', sha256: sha256(bytes), bytes: bytes.length };
}

function recoveryEvidenceFiles(recovery) {
  const output = [];
  const candidates = [recovery?.cases?.committedActionRecovery?.action?.evidence,
    recovery?.cases?.committedActionRecovery?.observer?.fenceEvidence?.evidence,
    recovery?.cases?.recoveryDeadlineExhaustion?.action?.evidence,
    ...(recovery?.cases?.recoveryDeadlineExhaustion?.recovery?.fenceEvidenceFiles ?? [])];
  for (const collector of Object.values(recovery?.collectorCases ?? {})) {
    candidates.push(collector?.action?.evidence, collector?.observer?.fenceEvidence,
      collector?.observer?.fenceEvidence?.evidence,
      ...(collector?.observer?.fenceEvidenceFiles ?? []));
  }
  for (const candidate of candidates) {
    if (candidate && typeof candidate.path === 'string' && HASH.test(candidate.sha256 ?? '')) output.push(candidate);
  }
  return [...new Map(output.map((row) => [`${row.path}\0${row.sha256}`, row])).values()];
}

export function combinedSourceRunIds({ completedRunId, committedRecoveryRunId, exhaustedRunId, blockerRunId, queuedRunId, collectorCases }) {
  const collectorKeys = collectorCases && typeof collectorCases === 'object' && !Array.isArray(collectorCases)
    ? Object.keys(collectorCases).sort() : [];
  demand(collectorKeys.join(',') === 'M3,S4' && UUID.test(completedRunId ?? '') &&
    committedRecoveryRunId === completedRunId && UUID.test(exhaustedRunId ?? '') &&
    UUID.test(blockerRunId ?? '') && UUID.test(queuedRunId ?? '') &&
    collectorKeys.every((key) => UUID.test(collectorCases[key]?.binding?.runId ?? '')),
  'combined_source_run_coverage_incomplete');
  return [...new Set([completedRunId, exhaustedRunId, blockerRunId, queuedRunId,
    collectorCases.S4.binding.runId, collectorCases.M3.binding.runId])];
}

async function verifyEvidenceFiles(commonCapture, references) {
  const verified = [];
  for (const reference of references) {
    demand(reference && typeof reference.path === 'string' && HASH.test(reference.sha256 ?? '') &&
      !reference.path.includes('\\') && !reference.path.startsWith('/') && !reference.path.split('/').some((part) => part === '..'),
    'combined_official_evidence_reference_invalid');
    const absolute = resolve(commonCapture.repoRoot, ...reference.path.split('/'));
    const info = await lstat(absolute);
    demand(info.isFile() && !info.isSymbolicLink(), 'combined_official_evidence_file_invalid');
    const bytes = await readFile(absolute);
    demand(sha256(bytes) === reference.sha256, 'combined_official_evidence_hash_mismatch');
    verified.push({ path: reference.path, sha256: reference.sha256, bytes: bytes.length,
      role: reference.role ?? 'runtime_evidence' });
  }
  return verified;
}

function parseJson(value, code) {
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { demand(false, code); }
  }
  return value;
}

function collectEvidenceReferences(value, found = []) {
  if (!value || typeof value !== 'object') return found;
  if (Array.isArray(value)) {
    for (const item of value) collectEvidenceReferences(item, found);
    return found;
  }
  if (typeof value.path === 'string' && HASH.test(value.sha256 ?? '') &&
      (value.boundary === 'actual_tool_http_x402_local_evm_application_store' || value.boundary === undefined)) {
    found.push({ path: value.path, sha256: value.sha256 });
  }
  for (const child of Object.values(value)) collectEvidenceReferences(child, found);
  return found;
}

async function readOfficialSourceEvidence(pool, commonCapture, runIds) {
  const databaseName = commonCapture.databaseIsolation.databaseName;
  const observed = await readonly(pool, databaseName, async (client) => {
    const runs = [];
    for (const runId of [...new Set(runIds)]) {
      const rowsForRun = rows(await client.query(`SELECT r.id::text,r.owner_id::text,r.agent_id::text,r.mode,r.status,r.terminal_reason,
          r.release_identity,r.manifest_hash,r.benchmark_hash,r.benchmark_version,r.policy_hash,r.task_ids,
          t.task_index,t.task_id,t.status AS task_status,t.closure_id::text,t.closure_status,t.closure_reason,
          e.result_hash,e.evaluator_source_hash,e.observation_evidence,e.result_json,e.case_hash,e.rubric_hash,
          b.bundle_hash,b.bundle_json,b.case_id,b.case_hash AS bundle_case_hash,b.rubric_hash AS bundle_rubric_hash,
          b.release_manifest_hash,b.environment_id,b.preparation_id::text,b.lease_id::text,b.generation_id::text,
          l.fence_evidence
        FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
        LEFT JOIN oid_run_task_evaluation e ON e.run_id=t.run_id AND e.task_index=t.task_index
        LEFT JOIN oid_run_task_observation_bundle b ON b.run_id=t.run_id AND b.task_index=t.task_index
        LEFT JOIN oid_task_preparation_intent p ON p.run_id=t.run_id AND p.task_index=t.task_index
        LEFT JOIN oid_task_environment_lease l ON l.preparation_id=p.preparation_id AND l.lease_id=p.lease_id
        WHERE r.id=$1::uuid ORDER BY t.task_index`, [runId]));
      demand(rowsForRun.length > 0 && rowsForRun.every((row) => row.id === runId), 'combined_source_run_not_found');
      const actionRows = rows(await client.query(`SELECT a.id::text,a.task_index,a.action_sequence::text,a.operation_id,a.action_kind,
          a.payload_hash,a.environment_id,a.access_generation,r.receipt_revision,r.receipt_status,r.evidence_hash,
          r.evidence_path,r.transaction_hash,o.status AS outbox_status,o.delivered_at::text
        FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
        JOIN oid_run_task_action_outbox o ON o.action_id=a.id WHERE a.run_id=$1::uuid
        ORDER BY a.task_index,a.action_sequence`, [runId]));
      const first = rowsForRun[0];
      const taskPins = rowsForRun.map((row) => {
        const result = row.result_json === null ? null : parseJson(row.result_json, 'combined_source_evaluation_json_invalid');
        const bundle = row.bundle_json === null ? null : parseJson(row.bundle_json, 'combined_source_bundle_json_invalid');
        const observationEvidence = row.observation_evidence === null ? null : parseJson(row.observation_evidence,
          'combined_source_observation_manifest_invalid');
        return { taskIndex: row.task_index, taskId: row.task_id, taskStatus: row.task_status,
          closureId: row.closure_id, closureStatus: row.closure_status, closureReason: row.closure_reason,
          casePin: row.case_id ? { caseId: row.case_id, caseHash: row.bundle_case_hash ?? row.case_hash,
            rubricHash: row.bundle_rubric_hash ?? row.rubric_hash, releaseManifestHash: row.release_manifest_hash,
            environmentId: row.environment_id, preparationId: row.preparation_id, leaseId: row.lease_id,
            generationId: row.generation_id } : null,
          evaluation: row.result_hash ? { resultHash: row.result_hash, evaluatorSourceHash: row.evaluator_source_hash,
            outcomeStatus: result?.status ?? null, outcome: result?.outcome ?? null, credit: result?.credit ?? null } : null,
          observationEvidence, bundleHash: row.bundle_hash,
          bundleBinding: bundle?.binding ?? null,
          bundleEvidenceReferences: collectEvidenceReferences(bundle, []),
          fenceEvidence: parseJson(row.fence_evidence, 'combined_source_fence_json_invalid') };
      });
      runs.push({ run: { id: first.id, ownerId: first.owner_id, agentId: first.agent_id, mode: first.mode,
          status: first.status, terminalReason: first.terminal_reason, releaseIdentity: first.release_identity,
          manifestHash: first.manifest_hash, benchmarkHash: first.benchmark_hash,
          benchmarkVersion: first.benchmark_version, policyHash: first.policy_hash, taskIds: first.task_ids },
        tasks: taskPins, actions: actionRows });
    }
    return { runs };
  });
  const refs = [];
  const evidenceRuns = observed.value.runs.map(({ run, tasks, actions }) => {
    for (const task of tasks) {
      refs.push(...collectEvidenceReferences(task.observationEvidence).map((row) => ({ ...row, role: 'observation_evidence' })));
      refs.push(...task.bundleEvidenceReferences.map((row) => ({ ...row, role: 'sealed_observation_bundle_evidence' })));
      const fence = task.fenceEvidence;
      if (fence?.evidence?.path && HASH.test(fence.evidence.sha256 ?? '')) refs.push({ path: fence.evidence.path,
        sha256: fence.evidence.sha256, role: 'generation_fence_evidence' });
    }
    for (const action of actions) {
      if (action.evidence_hash && action.evidence_path) refs.push({ path: action.evidence_path,
        sha256: action.evidence_hash, role: 'action_receipt_evidence' });
      demand(action.receipt_status !== 'pending' && action.outbox_status === 'delivered',
        'combined_source_action_receipt_or_outbox_incomplete');
    }
    return { run, tasks: tasks.map(({ observationEvidence, fenceEvidence, ...task }) => ({
      ...task,
      observationEvidenceReferences: collectEvidenceReferences(observationEvidence, []).map((row) => ({
        path: row.path, sha256: row.sha256 })),
      bundleEvidenceReferences: task.bundleEvidenceReferences,
      fence: fenceEvidence ? { confirmed: fenceEvidence.confirmed === true,
        preparationId: fenceEvidence.preparationId, leaseId: fenceEvidence.leaseId,
        generationId: fenceEvidence.generationId, environmentId: fenceEvidence.environmentId,
        evidence: fenceEvidence.evidence ? { path: fenceEvidence.evidence.path, sha256: fenceEvidence.evidence.sha256 } : null } : null,
    })), actions: actions.map((action) => ({ id: action.id, taskIndex: action.task_index,
      actionSequence: action.action_sequence, operationIdSha256: sha256(Buffer.from(action.operation_id)),
      actionKind: action.action_kind, payloadHash: action.payload_hash, environmentId: action.environment_id,
      accessGeneration: action.access_generation, receiptRevision: action.receipt_revision,
      receiptStatus: action.receipt_status, evidence: action.evidence_path && action.evidence_hash
        ? { path: action.evidence_path, sha256: action.evidence_hash } : null,
      transactionHash: action.transaction_hash, outboxStatus: action.outbox_status,
      deliveredAt: action.delivered_at })) };
  });
  demand(evidenceRuns.length === [...new Set(runIds)].length && evidenceRuns.every((entry) => {
    if (entry.run.status === 'completed') return entry.tasks.length > 0 && entry.tasks.every((task) =>
      task.casePin && HASH.test(task.bundleHash ?? '') && task.fence?.confirmed === true && task.evaluation);
    if (entry.run.terminalReason === 'platform_failure_recovery_exhausted') return entry.tasks.length > 0 &&
      entry.tasks.every((task) => task.fence?.confirmed === true && task.evaluation === null);
    if (entry.run.status === 'queued') return entry.tasks.length > 0 && entry.tasks.every((task) =>
      task.taskStatus === 'queued' && task.casePin === null && task.evaluation === null);
    return false;
  }),
  'combined_source_observation_bundle_or_pin_missing');
  const deduplicated = [...new Map(refs.map((row) => [`${row.path}\0${row.sha256}`, row])).values()];
  demand(deduplicated.length > 0 && evidenceRuns.some((entry) => entry.actions.some((action) => action.evidence)),
    'combined_source_actual_evidence_files_missing');
  const verified = await verifyEvidenceFiles(commonCapture, deduplicated);
  return { observer: observed.identity, runs: evidenceRuns, verifiedEvidenceFiles: verified };
}

async function readRestoredReport(pool, databaseName, ownerId, reportReceipt, privateDataDir) {
  const observer = await readonly(pool, databaseName, async (client) => {
    const report = rows(await client.query(`SELECT id::text,owner_id::text,source,operation_id,payload_hash,title,body,
        run_id::text,task_id,action_id::text,status,revision
      FROM oid_support_report WHERE id=$1::uuid AND owner_id=$2::uuid`, [reportReceipt.reportId, ownerId]));
    const uploads = rows(await client.query(`SELECT id::text,report_id::text,status,output_bytes::text,output_sha256,
        output_mime,storage_key::text,width,height FROM oid_support_image_upload
      WHERE report_id=$1::uuid ORDER BY id`, [reportReceipt.reportId]));
    return { report: report[0] ?? null, uploads };
  });
  const report = observer.value.report;
  demand(report && report.operation_id === reportReceipt.operationId && report.run_id === reportReceipt.payload.runId &&
    report.task_id === reportReceipt.payload.taskId && report.action_id === reportReceipt.payload.actionId &&
    report.status === reportReceipt.sourceStatus && report.revision === reportReceipt.sourceRevision &&
    report.source === 'owner' && report.payload_hash === reportReceipt.payloadHash,
  'combined_restored_report_binding_mismatch');
  const files = [];
  for (const upload of observer.value.uploads) {
    const filePath = resolve(privateDataDir, 'reports', 'images', `${upload.storage_key}.webp`);
    const fileInfo = await lstat(filePath);
    demand(fileInfo.isFile() && !fileInfo.isSymbolicLink(), 'combined_restored_report_image_missing');
    const bytes = await readFile(filePath);
    demand(bytes.length === Number(upload.output_bytes) && sha256(bytes) === upload.output_sha256 && upload.status === 'attached',
      'combined_restored_report_image_hash_mismatch');
    files.push({ uploadId: upload.id, bytes: bytes.length, sha256: upload.output_sha256, mime: upload.output_mime,
      width: upload.width, height: upload.height });
  }
  demand(files.length === reportReceipt.payload.imageUploadIds.length && files.length > 0,
    'combined_restored_report_image_count_mismatch');
  return { identity: observer.identity, report: { id: report.id, ownerId: report.owner_id, source: report.source,
    operationIdSha256: sha256(Buffer.from(report.operation_id)), payloadHash: report.payload_hash,
    titleSha256: sha256(Buffer.from(report.title)), bodySha256: sha256(Buffer.from(report.body)),
    runId: report.run_id, taskId: report.task_id, actionId: report.action_id, status: report.status, revision: report.revision },
    uploads: files };
}

async function restoredUiReads({ commonCapture, completedRun, queuedRun, reportReceipt, restoreResult, observerPool }) {
  const { ownerPage, adminPage, publicOrigin, ownerId } = commonCapture;
  await ownerPage.goto(`/runs?agentId=${encodeURIComponent(completedRun.agentId)}`, { waitUntil: 'domcontentloaded' });
  await ownerPage.getByTestId(`owner-run-${completedRun.runId}`).waitFor({ state: 'visible', timeout: 20_000 });
  await ownerPage.getByTestId(`owner-run-${queuedRun.runId}`).waitFor({ state: 'visible', timeout: 20_000 });
  const completedText = await ownerPage.getByTestId(`owner-run-status-${completedRun.runId}`).innerText();
  const queuedText = await ownerPage.getByTestId(`owner-run-status-${queuedRun.runId}`).innerText();
  demand(completedText === 'completed' && queuedText === 'queued', 'combined_restored_owner_run_ui_mismatch');
  await ownerPage.goto('/reports', { waitUntil: 'domcontentloaded' });
  const reportCard = ownerPage.locator('article.report-card').filter({ hasText: reportReceipt.payload.title });
  await reportCard.waitFor({ state: 'visible', timeout: 20_000 });
  const detailPromise = ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname === `/api/owner/reports/${reportReceipt.reportId}` && response.request().method() === 'GET',
  { timeout: 15_000 });
  const imageResponsePromise = ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname.startsWith(`/api/owner/reports/${reportReceipt.reportId}/images/`), { timeout: 15_000 });
  await reportCard.getByRole('button', { name: 'View private details' }).click();
  commonCapture.ownerCapture?.action?.('click', 'combined-restore-owner-report-details');
  const detailResponse = await detailPromise;
  const detail = await detailResponse.json().catch(() => ({}));
  demand(detailResponse.status() === 200 && detail?.report?.id === reportReceipt.reportId &&
    detail.report.links?.runId === reportReceipt.payload.runId && detail.report.links?.taskId === reportReceipt.payload.taskId &&
    detail.report.links?.actionId === reportReceipt.payload.actionId,
  'combined_restored_report_ui_detail_mismatch');
  const image = ownerPage.locator('[aria-label="Report details"] img').first();
  await image.waitFor({ state: 'visible', timeout: 15_000 });
  const imageResponse = await imageResponsePromise;
  demand(imageResponse.status() === 200, 'combined_restored_report_image_http_failed');
  const imageHash = sha256(await imageResponse.body());
  const restoredObserver = await readRestoredReport(observerPool, restoreResult.restoreDatabaseName, ownerId,
    reportReceipt, restoreResult.privateDataDir);
  demand(restoredObserver.uploads.some((row) => row.sha256 === imageHash), 'combined_restored_ui_image_not_bound_to_private_file');
  demand(adminPage && typeof adminPage.goto === 'function', 'combined_restored_admin_page_missing');
  const adminListPromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/admin/reports' && response.request().method() === 'GET', { timeout: 20_000 });
  await adminPage.goto(new URL('/admin/reports', publicOrigin).toString(), { waitUntil: 'domcontentloaded' });
  const adminListResponse = await adminListPromise;
  const adminRow = adminPage.locator('tbody tr[data-report-id="' + reportReceipt.reportId + '"]');
  await adminRow.waitFor({ state: 'visible', timeout: 20_000 });
  const adminRowReportId = await adminRow.getAttribute('data-report-id');
  const adminRowStatus = (await adminRow.locator('td').nth(3).innerText()).trim();
  const adminDetailPromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/admin/reports/' + reportReceipt.reportId && response.request().method() === 'GET',
  { timeout: 15_000 });
  const adminImageId = reportReceipt.payload.imageUploadIds[0];
  const adminImagePromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/admin/reports/' + reportReceipt.reportId + '/images/' + adminImageId,
  { timeout: 15_000 });
  await adminRow.getByRole('button', { name: 'Open', exact: true }).click();
  commonCapture.adminCapture?.action?.('click', 'combined-restore-admin-report-details');
  const adminDetailResponse = await adminDetailPromise;
  const adminDetailPayload = await adminDetailResponse.json().catch(() => ({}));
  const adminImage = adminPage.locator('[aria-label="Selected private report"] img').first();
  await adminImage.waitFor({ state: 'visible', timeout: 15_000 });
  const adminImageResponse = await adminImagePromise;
  const adminImageHash = sha256(await adminImageResponse.body());
  const adminReport = adminDetailPayload?.report;
  const adminDetails = adminPage.locator('[aria-label="Selected private report"]');
  await adminDetails.getByText(
    'owner report · revision ' + reportReceipt.sourceRevision, { exact: true }).waitFor({ state: 'visible', timeout: 10_000 });
  const adminRenderedTitle = await adminDetails.locator('h2').innerText();
  const expectedAdminStatus = reportReceipt.sourceStatus.replace('_', ' ');
  demand(adminListResponse.status() === 200 && adminRowReportId === reportReceipt.reportId &&
    adminRowStatus === expectedAdminStatus && adminRenderedTitle === reportReceipt.payload.title &&
    adminDetailResponse.status() === 200 && adminReport?.id === reportReceipt.reportId &&
    adminReport.source === 'owner' && adminReport.status === reportReceipt.sourceStatus &&
    adminReport.revision === reportReceipt.sourceRevision &&
    adminReport.links?.runId === reportReceipt.payload.runId && adminReport.links?.taskId === reportReceipt.payload.taskId &&
    adminReport.links?.actionId === reportReceipt.payload.actionId &&
    adminImageResponse.status() === 200 && adminImageHash === imageHash,
  'combined_restored_admin_report_ui_mismatch');
  return { ui: { completedRunStatus: completedText, queuedRunStatus: queuedText,
    reportDetailStatus: detailResponse.status(), imageStatus: imageResponse.status(), imageSha256: imageHash },
    admin: { listStatus: adminListResponse.status(), detailStatus: adminDetailResponse.status(),
      imageStatus: adminImageResponse.status(), reportId: adminReport.id, source: adminReport.source,
      status: adminReport.status, revision: adminReport.revision, runId: adminReport.links.runId,
      taskId: adminReport.links.taskId, actionId: adminReport.links.actionId, imageSha256: adminImageHash },
    observer: restoredObserver };
}

async function verifyExpiredReportAccess({ commonCapture, reportReceipt }) {
  const ownerPage = commonCapture.ownerPage;
  const listPromise = ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/owner/reports' && response.request().method() === 'GET', { timeout: 20_000 });
  await ownerPage.goto(new URL('/reports', commonCapture.publicOrigin).toString(), { waitUntil: 'domcontentloaded' });
  const listResponse = await listPromise;
  const listBody = await listResponse.json().catch(() => ({}));
  await ownerPage.getByRole('alert').waitFor({ state: 'visible', timeout: 15_000 });
  demand(listResponse.status() === 410 && listBody?.error?.code === 'REPORT_RETENTION_EXPIRED',
    'combined_expired_report_list_not_denied');
  const detailResponse = await ownerPage.request.get(new URL(`/api/owner/reports/${reportReceipt.reportId}`,
    commonCapture.publicOrigin).toString());
  const detailBody = await detailResponse.json().catch(() => ({}));
  demand(detailResponse.status() === 410 && detailBody?.error?.code === 'REPORT_RETENTION_EXPIRED',
    'combined_expired_report_detail_not_denied');
  const imageId = reportReceipt.payload.imageUploadIds[0];
  const imageResponse = await ownerPage.request.get(new URL(`/api/owner/reports/${reportReceipt.reportId}/images/${imageId}`,
    commonCapture.publicOrigin).toString());
  const imageBody = await imageResponse.json().catch(() => ({}));
  demand(imageResponse.status() === 410 && imageBody?.error?.code === 'REPORT_RETENTION_EXPIRED',
    'combined_expired_report_image_not_denied');
  return { ui: { pagePath: '/reports', expiredNoticeVisible: true, listStatus: listResponse.status(),
      listErrorCode: listBody.error.code },
    reportDetail: { status: detailResponse.status(), errorCode: detailBody.error.code },
    image: { status: imageResponse.status(), errorCode: imageBody.error.code,
      reportIdSha256: sha256(Buffer.from(reportReceipt.reportId)), imageIdSha256: sha256(Buffer.from(imageId)) } };
}

async function retryOriginalOperations({ commonCapture, completedRun, reportReceipt, retentionExpired = false }) {
  const ownerPage = commonCapture.ownerPage;
  demand(reportReceipt?.payload && completedRun?.queue?.intentCreatePayload && completedRun?.blocker?.intentCreatePayload &&
    completedRun?.recovery?.intentCreatePayload && typeof completedRun.redemptionPayload?.code === 'string',
  'combined_original_operation_retry_material_missing');
  const runBinding = (value) => ({ intentId: value.intentId, runId: value.runId,
    intentOperationIdSha256: sha256(Buffer.from(value.createIntentOperationId)),
    acceptOperationIdSha256: sha256(Buffer.from(value.acceptOperationId)) });
  const originalReceiptBindings = {
    recoveryRun: runBinding(completedRun.recovery),
    blockerRun: runBinding(completedRun.blocker),
    queuedRun: runBinding(completedRun.queue),
    bonusRedemption: { redemptionId: completedRun.redemption.redemptionId, grantId: completedRun.redemption.grantId,
      codeId: completedRun.redemption.codeId, operationIdSha256: sha256(Buffer.from(completedRun.redemption.operationId)) },
    report: { reportId: reportReceipt.reportId, operationIdSha256: sha256(Buffer.from(reportReceipt.operationId)) },
  };
  const replayRunOperations = async (label, value, expectedStatus) => {
    demand(value && UUID.test(value.intentId ?? '') && UUID.test(value.runId ?? '') &&
      value.intentCreatePayload?.operationId && value.intentCreatePayload.operationId === value.createIntentOperationId &&
      typeof value.acceptOperationId === 'string' &&
      typeof value.agentBearer === 'string' && value.agentBearer.length >= 32,
    `combined_${label}_retry_material_invalid`);
    const intentResponse = await ownerPage.request.post(new URL('/api/owner/runs/intents', commonCapture.publicOrigin).toString(), {
      headers: { origin: commonCapture.publicOrigin, 'content-type': 'application/json' }, data: value.intentCreatePayload,
    });
    const intentBody = await intentResponse.json().catch(() => ({}));
    demand(intentResponse.status() === 200 && intentBody?.replayed === true &&
      intentBody?.intent?.id === value.intentId, `combined_${label}_intent_retry_failed`);
    const acceptResponse = await ownerPage.request.post(new URL(`/api/agent/run-intents/${value.intentId}/accept`, commonCapture.publicOrigin).toString(), {
      headers: { authorization: `Bearer ${value.agentBearer}`, origin: commonCapture.publicOrigin,
        'content-type': 'application/json' }, data: { operationId: value.acceptOperationId },
    });
    const acceptBody = await acceptResponse.json().catch(() => ({}));
    demand(acceptResponse.status() === 200 && acceptBody?.replayed === true &&
      acceptBody?.run?.id === value.runId && acceptBody?.run?.status === expectedStatus,
    `combined_${label}_accept_retry_failed`);
    return { intent: { status: intentResponse.status(), replayed: intentBody.replayed,
        operationIdSha256: sha256(Buffer.from(value.intentCreatePayload.operationId)), intentId: value.intentId },
      accept: { status: acceptResponse.status(), replayed: acceptBody.replayed,
        operationIdSha256: sha256(Buffer.from(value.acceptOperationId)), runId: acceptBody.run.id,
        runStatus: acceptBody.run.status } };
  };
  const recoveryRun = await replayRunOperations('recovery_run', completedRun.recovery, 'completed');
  const blockerRun = await replayRunOperations('blocker_run', completedRun.blocker, 'completed');
  const queuedRun = await replayRunOperations('queued_run', { ...completedRun.queue,
    agentBearer: completedRun.blocker.agentBearer }, 'queued');
  const redemptionPayload = completedRun.redemptionPayload;
  const redemptionResponse = await ownerPage.request.post(new URL('/api/owner/bonus-codes/redeem', commonCapture.publicOrigin).toString(), {
    headers: { origin: commonCapture.publicOrigin, 'content-type': 'application/json' }, data: redemptionPayload,
  });
  const redemptionBody = await redemptionResponse.json().catch(() => ({}));
  demand(redemptionResponse.status() === 200 && redemptionBody?.replayed === true &&
    redemptionBody?.operationId === completedRun.redemption.operationId &&
    redemptionBody?.redemption?.id === completedRun.redemption.redemptionId &&
    redemptionBody?.redemption?.grantId === completedRun.redemption.grantId &&
    redemptionBody?.redemption?.codeId === completedRun.redemption.codeId,
  'combined_original_bonus_redemption_retry_failed');
  let report = { status: null, replayed: false, reportId: reportReceipt.reportId };
  if (retentionExpired) {
    report = { status: 'not_submitted_after_expiry', replayed: false, reportId: reportReceipt.reportId,
      operationIdSha256: originalReceiptBindings.report.operationIdSha256 };
  } else {
    const reportResponse = await ownerPage.request.post(new URL('/api/owner/reports', commonCapture.publicOrigin).toString(), {
      headers: { origin: commonCapture.publicOrigin, 'content-type': 'application/json' }, data: reportReceipt.payload,
    });
    const reportBody = await reportResponse.json().catch(() => ({}));
    demand(reportResponse.status() === 200 && reportBody?.replayed === true &&
      reportBody?.report?.id === reportReceipt.reportId, 'combined_original_report_retry_failed');
    report = { status: reportResponse.status(), replayed: reportBody.replayed,
      operationIdSha256: sha256(Buffer.from(reportReceipt.operationId)), reportId: reportBody.report.id };
  }
  return { status: 'verified', retryTransport: 'same_origin_authenticated_playwright_http',
    recoveryRun, blockerRun, queuedRun,
    bonusRedemption: { status: redemptionResponse.status(), replayed: redemptionBody.replayed,
      operationIdSha256: sha256(Buffer.from(redemptionPayload.operationId)), operationPayloadSha256: sha256(Buffer.from(JSON.stringify(redemptionPayload))),
      redemptionId: redemptionBody.redemption.id, grantId: redemptionBody.redemption.grantId,
      codeId: redemptionBody.redemption.codeId },
    report,
    originalReceiptBindings,
    reportOperationDisposition: retentionExpired ? 'expired_content_not_replayed' : 'same_receipts_replayed' };
}

function projectRestore(restore) {
  return { schemaVersion: restore.schemaVersion, status: restore.status, boundary: restore.boundary,
    checkpointId: restore.checkpointId, sourceDatabase: restore.sourceDatabase,
    restoreDatabaseName: restore.restoreDatabaseName, checkpoint: restore.checkpoint,
    creationReceipt: restore.creationReceipt, restoreReceipt: restore.restoreReceipt,
    authoritativeClosure: restore.authoritativeClosure, originalIds: restore.originalIds,
    operationBindings: restore.operationBindings, retention: restore.retention,
    observations: Object.fromEntries(Object.entries(restore.observations ?? {}).map(([key, value]) =>
      [key, projectObserverSnapshot(value)])),
    timing: restore.timing, writesMayBeEnabled: restore.writesMayBeEnabled,
    targetHostAcceptance: restore.targetHostAcceptance };
}

function projectObserverSnapshot(snapshot) {
  demand(snapshot && typeof snapshot === 'object' && !Array.isArray(snapshot) &&
    snapshot.observerIdentity?.databaseRole === 'oid_observer' &&
    snapshot.observerIdentity.transactionReadOnly === 'on' &&
    HASH.test(snapshot.databaseTotalsSha256 ?? '') && HASH.test(snapshot.financialStateSha256 ?? '') &&
    HASH.test(snapshot.benchmarkStateSha256 ?? '') && HASH.test(snapshot.reportStateSha256 ?? '') &&
    HASH.test(snapshot.reportRateLimitStateSha256 ?? '') && HASH.test(snapshot.controlOperationalStateSha256 ?? ''),
  'combined_observer_snapshot_projection_invalid');
  const imageFiles = Array.isArray(snapshot.imageFiles) ? snapshot.imageFiles.map((row) => ({
    bytes: row.bytes, sha256: row.sha256,
  })).sort((left, right) => left.sha256.localeCompare(right.sha256)) : null;
  const reportDeletionReceipts = Array.isArray(snapshot.reportDeletionReceipts)
    ? snapshot.reportDeletionReceipts.map((row) => ({ reportId: row.reportId, status: row.status }))
      .sort((left, right) => left.reportId.localeCompare(right.reportId))
    : null;
  demand(imageFiles && imageFiles.every((row) => Number.isSafeInteger(row.bytes) && row.bytes >= 0 && HASH.test(row.sha256 ?? '')) &&
    reportDeletionReceipts && reportDeletionReceipts.every((row) => typeof row.status === 'string'),
  'combined_observer_projection_collections_invalid');
  const tableFingerprints = snapshot.tableFingerprints && typeof snapshot.tableFingerprints === 'object' &&
    !Array.isArray(snapshot.tableFingerprints) ? snapshot.tableFingerprints : null;
  demand(tableFingerprints && Object.values(tableFingerprints).every((row) => row &&
    Number.isSafeInteger(row.rowCount) && row.rowCount >= 0 && HASH.test(row.sha256 ?? '')),
  'combined_observer_projection_fingerprints_invalid');
  const projection = {
    schemaVersion: snapshot.schemaVersion,
    sourceDatabase: snapshot.sourceDatabase,
    observerIdentity: snapshot.observerIdentity,
    snapshotBoundary: snapshot.snapshotBoundary,
    snapshotBoundaryId: snapshot.snapshotBoundaryId,
    snapshotAt: snapshot.snapshotAt,
    sourceBuildSha256: snapshot.sourceBuildSha256,
    tableFingerprints,
    sequenceSha256: snapshot.sequenceSha256,
    databaseTotalsSha256: snapshot.databaseTotalsSha256,
    financialStateSha256: snapshot.financialStateSha256,
    benchmarkStateSha256: snapshot.benchmarkStateSha256,
    reportStateSha256: snapshot.reportStateSha256,
    reportRateLimitStateSha256: snapshot.reportRateLimitStateSha256,
    controlOperationalStateSha256: snapshot.controlOperationalStateSha256,
    operationBindings: snapshot.operationBindings,
    originalIds: snapshot.originalIds,
    imageFiles,
    imageFilesSha256: sha256(Buffer.from(JSON.stringify(imageFiles))),
    reportDeletionReceipts,
    reportDeletionReceiptsSha256: sha256(Buffer.from(JSON.stringify(
      [...snapshot.reportDeletionReceipts].map((row) => ({ reportId: row.reportId, status: row.status }))
        .sort((left, right) => left.reportId.localeCompare(right.reportId))))),
    reportCount: snapshot.reportCount,
    uploadCount: snapshot.uploadCount,
    pendingUploadGcReceipts: snapshot.pendingUploadGcReceipts,
  };
  assertSecretFree(projection, 'combined_observer_projection');
  return projection;
}

/** Verify the original DB remained unchanged while the restored clones served reads and retries. */
export function verifyPostRestoreSourceStability({ checkpointSourceAfter, afterRestore, sourceDatabase }) {
  demand(typeof sourceDatabase === 'string' && /^oid_acceptance_[a-f0-9]{32}$/.test(sourceDatabase),
    'combined_source_after_restore_database_invalid');
  const validateSourceSnapshotShape = (snapshot) => {
    const bindings = snapshot?.operationBindings;
    const ids = snapshot?.originalIds;
    const tableFingerprints = snapshot?.tableFingerprints;
    demand(snapshot?.schemaVersion === 'beta-combined-source-observation/v1' &&
      snapshot.snapshotBoundary === 'admission_frozen_database_quiescent' &&
      typeof snapshot.snapshotBoundaryId === 'string' && snapshot.snapshotBoundaryId.length >= 16 &&
      typeof snapshot.snapshotAt === 'string' && Number.isFinite(Date.parse(snapshot.snapshotAt)) &&
      HASH.test(snapshot.sourceBuildSha256 ?? '') && tableFingerprints && typeof tableFingerprints === 'object' &&
      !Array.isArray(tableFingerprints) && REQUIRED_SOURCE_TABLES.every((name) => Object.hasOwn(tableFingerprints, name)) &&
      HASH.test(snapshot.sequenceSha256 ?? '') && HASH.test(snapshot.databaseTotalsSha256 ?? ''),
    'combined_source_after_restore_snapshot_incomplete');
    demand(bindings && typeof bindings === 'object' && !Array.isArray(bindings) &&
      ['bonusGrantOperationsSha256', 'runOperationReceiptsSha256', 'runGenerationReceiptsSha256',
        'reportOperationReceiptsSha256'].every((key) => HASH.test(bindings[key] ?? '')) &&
      ['bonusGrantOperationCount', 'runOperationReceiptCount', 'runGenerationReceiptCount',
        'reportOperationReceiptCount'].every((key) => Number.isSafeInteger(bindings[key]) && bindings[key] >= 0),
    'combined_source_after_restore_bindings_missing');
    demand(ids && typeof ids === 'object' && !Array.isArray(ids) &&
      ['completedRunIds', 'queuedInterruptedUnknownRunIds', 'operationIds', 'bonusGrantOperationIds',
        'reportOperationIds'].every((key) => Array.isArray(ids[key]) && ids[key].every((id) => typeof id === 'string')),
    'combined_source_after_restore_ids_missing');
  };
  validateSourceSnapshotShape(checkpointSourceAfter);
  validateSourceSnapshotShape(afterRestore);
  const before = projectObserverSnapshot(checkpointSourceAfter);
  const after = projectObserverSnapshot(afterRestore);
  demand(before.sourceDatabase === sourceDatabase && after.sourceDatabase === sourceDatabase &&
    before.observerIdentity.databaseName === sourceDatabase && after.observerIdentity.databaseName === sourceDatabase &&
    before.observerIdentity.databaseRole === 'oid_observer' && after.observerIdentity.databaseRole === 'oid_observer' &&
    before.observerIdentity.transactionReadOnly === 'on' && after.observerIdentity.transactionReadOnly === 'on',
  'combined_source_after_restore_observer_identity_invalid');
  const comparisons = {
    sourceBuild: before.sourceBuildSha256 === after.sourceBuildSha256,
    tables: canonical(before.tableFingerprints) === canonical(after.tableFingerprints),
    sequences: before.sequenceSha256 === after.sequenceSha256,
    databaseTotals: before.databaseTotalsSha256 === after.databaseTotalsSha256,
    financial: before.financialStateSha256 === after.financialStateSha256,
    benchmark: before.benchmarkStateSha256 === after.benchmarkStateSha256,
    reports: before.reportStateSha256 === after.reportStateSha256,
    reportRateLimits: before.reportRateLimitStateSha256 === after.reportRateLimitStateSha256,
    controlState: before.controlOperationalStateSha256 === after.controlOperationalStateSha256,
    operationBindings: canonical(before.operationBindings) === canonical(after.operationBindings),
    originalIds: canonical(before.originalIds) === canonical(after.originalIds),
    images: canonical(before.imageFiles) === canonical(after.imageFiles),
    deletionReceipts: canonical(before.reportDeletionReceipts) === canonical(after.reportDeletionReceipts),
    supportCounts: before.reportCount === after.reportCount && before.uploadCount === after.uploadCount &&
      before.pendingUploadGcReceipts === after.pendingUploadGcReceipts,
  };
  demand(Object.values(comparisons).every(Boolean), 'combined_source_database_changed_after_restores');
  return {
    status: 'verified',
    sourceDatabase,
    checkpointSourceSnapshotAt: before.snapshotAt,
    afterRestoreSnapshotAt: after.snapshotAt,
    comparisons,
  };
}

export async function runBetaQueuePreparationCases({ commonCapture, progress: progressFn }) {
  const expectedDatabase = commonCapture?.databaseIsolation?.databaseName;
  demand(/^oid_acceptance_[a-f0-9]{32}$/.test(expectedDatabase ?? '') &&
    typeof commonCapture?.observerDatabaseUrl === 'string' && typeof commonCapture?.publicOrigin === 'string' &&
    commonCapture.ownerPage && commonCapture.adminPage && UUID.test(commonCapture.ownerId ?? '') &&
    UUID.test(commonCapture.adminOwnerId ?? '') && commonCapture.genuineCaptureInput,
  'combined_queue_capture_prerequisites_missing');
  const observerPool = new Pool({ connectionString: commonCapture.observerDatabaseUrl, max: 2,
    application_name: 'bpc-combined-queue-observer' });
  try {
    const initialControl = await readOperationsControl(observerPool, expectedDatabase);
    demand(initialControl.identity?.role === 'oid_observer' && initialControl.identity.transactionReadOnly === 'on' &&
      initialControl.identity.databaseName === expectedDatabase && initialControl.value.control?.mode === 'active',
    'combined_queue_initial_observer_or_control_invalid');
    await progressFn?.({ component: 'beta_combined_queue', phase: 'active_blocker_and_queue_begin' });
    const result = await runActiveBlockerWithQueuedPausedRun({ commonCapture, observerPool, progressFn });
    // AICODE-NOTE: This focused queue probe persists durable admission evidence only; bearer credentials and the one-time bonus code stay in RAM for the combined restore path.
    const output = { schemaVersion: 'beta-combined-queue/v1', status: 'verified', capture: result.capture };
    assertSecretFree(output, 'beta-combined-queue');
    return output;
  } finally {
    await observerPool.end();
  }
}

export async function runBetaCombinedRestoreCases({ commonCapture, recoveryFaultProxy, recoveryObserverProxy, progress: progressFn }) {
  const expectedDatabase = commonCapture?.databaseIsolation?.databaseName;
  demand(/^oid_acceptance_[a-f0-9]{32}$/.test(expectedDatabase ?? '') &&
    typeof commonCapture.executeReportCases === 'function' && typeof commonCapture.createCombinedBackup === 'function' &&
    typeof commonCapture.startRestoredApi === 'function' && typeof commonCapture.stopApi === 'function' &&
    typeof commonCapture.getRuntimeRecoverySecrets === 'function' && isAbsolute(commonCapture.repoRoot ?? '') &&
    commonCapture.sourceInputsBeforeCheckpoint && HASH.test(commonCapture.sourceInputsBeforeCheckpoint.sha256 ?? ''),
  'combined_restore_capture_prerequisites_missing');
  const ownerPool = new Pool({ connectionString: commonCapture.observerDatabaseUrl, max: 2,
    application_name: 'bpc-combined-restore-source-observer' });
  let sourceObserverClosed = false;
  let completedCredential = null;
  let blockerRetryMaterial = null;
  let reportReceipt = null;
  let provider;
  let restoredApiStarted = false;
  try {
    await progressFn?.({ component: 'beta_combined_restore', phase: 'platform_recovery_begin', databaseName: expectedDatabase });
    const recovery = await runBetaRecoveryCases({ commonCapture, recoveryFaultProxy, recoveryObserverProxy, progress: progressFn,
      onGenuineRunCompleted: (event) => {
        demand(!completedCredential && UUID.test(event.runId) && UUID.test(event.agentId) &&
          typeof event.agentBearer === 'string' && event.agentBearer.length >= 32 &&
          UUID.test(event.intentId ?? '') && typeof event.createIntentOperationId === 'string' &&
          typeof event.acceptOperationId === 'string' && event.intentCreatePayload?.operationId === event.createIntentOperationId,
        'combined_completed_run_credential_callback_invalid');
        completedCredential = { runId: event.runId, ownerId: event.ownerId, agentId: event.agentId,
          mode: event.mode, taskIds: [...event.taskIds], agentBearer: event.agentBearer,
          intentId: event.intentId, createIntentOperationId: event.createIntentOperationId,
          acceptOperationId: event.acceptOperationId, intentCreatePayload: structuredClone(event.intentCreatePayload),
          releaseIdentity: event.releaseIdentity, manifestHash: event.manifestHash };
      } });
    demand(recovery.status === 'verified' && recovery.scenarioId === 'BPC-SC-017' &&
      recovery.cases?.committedActionRecovery?.genuineRun?.runCompletion?.runStatus === 'completed' &&
      recovery.cases?.committedActionRecovery?.action?.finalReceiptStatus === 'observed' &&
      recovery.cases?.recoveryDeadlineExhaustion?.genuineRun?.status === 'captured_platform_recovery_exhausted_without_grade',
    'combined_platform_recovery_cases_not_verified');
    const completedRecovery = recovery.cases.committedActionRecovery;
    demand(completedCredential?.runId === completedRecovery.binding.runId && completedCredential.ownerId === commonCapture.ownerId,
      'combined_completed_run_credential_not_bound_to_recovery');
    const completedActionId = completedRecovery.action.actionId;
    demand(UUID.test(completedActionId ?? '') && completedRecovery.binding.taskId === 'S1',
      'combined_completed_run_action_context_missing');

    await progressFn?.({ component: 'beta_combined_restore', phase: 'human_report_begin', runId: completedCredential.runId });
    const reportCases = await commonCapture.executeReportCases({
      genuineRunContext: { runId: completedCredential.runId, agentId: completedCredential.agentId,
        taskId: 'S1', actionId: completedActionId },
      onAcceptedReport: async (event) => {
        demand(!reportReceipt && UUID.test(event.reportId ?? '') && typeof event.operationId === 'string' &&
          event.payload?.operationId === event.operationId && event.payload.runId === completedCredential.runId &&
          event.payload.taskId === 'S1' && event.payload.actionId === completedActionId &&
          Array.isArray(event.payload.imageUploadIds) && event.payload.imageUploadIds.length === 1 &&
          [200, 201].includes(event.responseStatus), 'combined_report_memory_callback_invalid');
        const persisted = await readonly(ownerPool, expectedDatabase, async (client) => rows(await client.query(
          'SELECT payload_hash FROM oid_support_report WHERE id=$1::uuid AND operation_id=$2',
          [event.reportId, event.operationId])));
        demand(persisted.value.length === 1 && HASH.test(persisted.value[0].payload_hash),
          'combined_original_report_payload_receipt_missing');
        reportReceipt = { reportId: event.reportId, operationId: event.operationId,
          payload: structuredClone(event.payload), payloadHash: persisted.value[0].payload_hash,
          responseStatus: event.responseStatus, replayed: event.replayed };
      },
    });
    demand(reportReceipt && reportCases?.scenarioData?.['BPC-SC-018']?.localStatus === 'observed_partial' &&
      reportCases.scenarioData['BPC-SC-026']?.localStatus === 'observed_partial', 'combined_report_ui_case_incomplete');
    const sourceReportState = await readonly(ownerPool, expectedDatabase, async (client) => rows(await client.query(
      'SELECT status,revision FROM oid_support_report WHERE id=$1::uuid', [reportReceipt.reportId])));
    demand(sourceReportState.value.length === 1, 'combined_source_report_state_missing');
    reportReceipt.sourceStatus = sourceReportState.value[0].status;
    reportReceipt.sourceRevision = sourceReportState.value[0].revision;

    await progressFn?.({ component: 'beta_combined_restore', phase: 'active_blocker_and_queue_begin', ownerId: commonCapture.ownerId });
    const blockerResult = await runActiveBlockerWithQueuedPausedRun({ commonCapture, observerPool: ownerPool, progressFn });
    blockerRetryMaterial = blockerResult.retryMaterial;
    const queue = blockerResult.capture.queue;
    const paused = blockerResult.capture.pause;
    const workerRun = blockerResult.capture.activeRunDrain;
    const pausedQueue = blockerResult.capture.queuedAfterDrain;

    const evidenceRootRelative = `artifacts/runs/beta-combined-restore-source/${commonCapture.runId}`;
    const evidenceRoot = resolve(commonCapture.repoRoot, ...evidenceRootRelative.split('/'));
    await mkdir(evidenceRoot, { recursive: true, mode: 0o700 });
    const evidenceFiles = [];
    const add = async (name, value) => {
      assertSecretFree(value, `combined-restore-${name}`);
      evidenceFiles.push(await writeEvidenceFile(commonCapture.repoRoot,
        `${evidenceRootRelative}/${name}.json`, value));
    };
    const reportEvidence = { schemaVersion: 'bpc-combined-report-evidence/v1',
      databaseName: expectedDatabase, runContext: { runId: completedCredential.runId, taskId: 'S1', actionId: completedActionId },
      reportReceipt: { reportId: reportReceipt.reportId, operationIdSha256: sha256(Buffer.from(reportReceipt.operationId)),
        payloadSha256: reportReceipt.payloadHash, imageUploadIdsSha256: reportReceipt.payload.imageUploadIds.map((id) => sha256(Buffer.from(id))),
        responseStatus: reportReceipt.responseStatus },
      cases: { SC018: reportCases.scenarioData['BPC-SC-018'], SC026: reportCases.scenarioData['BPC-SC-026'] } };
    await add('platform-recovery', recovery);
    await add('report-runtime', reportEvidence);
    await add('active-blocker-queue-pause', blockerResult.capture);
    const sourceInputPath = commonCapture.sourceInputsBeforeCheckpoint.path;
    demand(typeof sourceInputPath === 'string' && !sourceInputPath.startsWith('/') && !sourceInputPath.includes('\\'),
      'combined_source_inventory_path_invalid');
    const sourceInputBytes = await readFile(resolve(commonCapture.repoRoot, ...sourceInputPath.split('/')));
    demand(sha256(sourceInputBytes) === commonCapture.sourceInputsBeforeCheckpoint.sha256,
      'combined_source_inventory_hash_mismatch');
    const sourceRunIds = combinedSourceRunIds({ completedRunId: completedCredential.runId,
      committedRecoveryRunId: recovery.cases.committedActionRecovery?.binding?.runId,
      exhaustedRunId: recovery.cases.recoveryDeadlineExhaustion?.binding?.runId,
      blockerRunId: blockerResult.capture.blockerRun.runId, queuedRunId: queue.runId,
      collectorCases: recovery.collectorCases });
    const sourceObservation = await readOfficialSourceEvidence(ownerPool, commonCapture, sourceRunIds);
    const sourceObservationFile = await add('source-observations', { schemaVersion: 'bpc-combined-source-observation/v1',
      boundary: 'independent_readonly_oid_observer_before_host_checkpoint', ...sourceObservation });
    const officialFiles = [...evidenceFiles, { relativePath: sourceInputPath, sourcePath: sourceInputPath,
      role: 'source_inputs_before', sha256: commonCapture.sourceInputsBeforeCheckpoint.sha256 }];
    for (const reference of [...sourceObservation.verifiedEvidenceFiles,
      ...recoveryEvidenceFiles(recovery).map((row) => ({ ...row, role: 'platform_recovery_evidence' }))]) {
      officialFiles.push({ relativePath: reference.path, sourcePath: reference.path,
        role: reference.role ?? 'platform_recovery_evidence', sha256: reference.sha256 });
    }
    const uniqueOfficialFilesByPath = new Map();
    for (const file of officialFiles) {
      const key = file.relativePath.toLowerCase();
      const previous = uniqueOfficialFilesByPath.get(key);
      demand(!previous || previous.sha256 === file.sha256, 'combined_official_evidence_conflicting_hashes');
      if (!previous) uniqueOfficialFilesByPath.set(key, file);
    }
    const uniqueOfficialFiles = [...uniqueOfficialFilesByPath.values()];
    const verifiedEvidenceFiles = await verifyEvidenceFiles(commonCapture, uniqueOfficialFiles.map((row) => ({
      path: row.sourcePath, sha256: row.sha256 ?? null,
    })).filter((row) => row.sha256));
    const officialEvidenceRefs = { sourceProfile: 'local_isolated_beta_combined_restore', runIds: [...new Set(sourceRunIds)],
      sourceBuildSha256: commonCapture.sourceBuildSha256,
      files: uniqueOfficialFiles.map(({ relativePath, sourcePath, role }) => ({ relativePath, sourcePath, role })) };

    await progressFn?.({ component: 'beta_combined_restore', phase: 'checkpoint_freeze_begin', runId: completedCredential.runId,
      queuedRunId: queue.runId, reports: 1 });
    // The consistent-checkpoint boundary requires the source to be unserved
    // and have no other clients. Its own independent pre-checkpoint read is done.
    await ownerPool.end();
    sourceObserverClosed = true;
    provider = await commonCapture.createCombinedBackup({ officialEvidenceRefs, kind: 'pre_migration' });
    const checkpoint = await provider.createCheckpoint();
    demand(checkpoint?.status === 'checkpoint_verified' && checkpoint.writesMayBeEnabled === false &&
      checkpoint.source?.before?.originalIds?.completedRunIds?.includes(completedCredential.runId) &&
      checkpoint.source?.before?.originalIds?.queuedInterruptedUnknownRunIds?.includes(queue.runId),
    'combined_checkpoint_did_not_bind_completed_and_queued_runs');
    const sourceIds = checkpoint.originalIds;
    demand(sourceIds?.reportOperationIds?.some((id) => id === reportReceipt.operationId) &&
      sourceIds?.bonusGrantOperationIds?.length > 0 && sourceIds?.operationIds?.length > 0,
    'combined_checkpoint_original_operation_ids_incomplete');

    await progressFn?.({ component: 'beta_combined_restore', phase: 'isolated_restore_begin', checkpointId: checkpoint.checkpointId,
      sourceDatabase: expectedDatabase });
    const restoreResult = await provider.restoreCheckpoint();
    demand(restoreResult?.status === 'verified_unserved' && restoreResult.writesMayBeEnabled === false &&
      restoreResult.targetHostAcceptance === 'not_run' && restoreResult.retention?.expired === false,
    'combined_restore_not_verified_unserved');
    const restoredDatabaseUrl = restoreResult.takeRestoredDatabaseUrl();
    const restoredSecrets = restoreResult.takeRuntimeSecrets();
    await commonCapture.startRestoredApi({ databaseUrl: restoredDatabaseUrl, privateDataDir: restoreResult.privateDataDir,
      closureStatePath: restoreResult.closureStatePath, captureIsolationRoot: restoreResult.captureIsolationRoot,
      recoveredSecrets: restoredSecrets });
    restoredApiStarted = true;
    for (const key of Object.keys(restoredSecrets)) restoredSecrets[key] = '';
    const restoredObserverUrl = withDatabase(commonCapture.observerDatabaseUrl, restoreResult.restoreDatabaseName);
    const restoredPool = new Pool({ connectionString: restoredObserverUrl, max: 2,
      application_name: 'bpc-combined-restore-independent-observer' });
    let restoredReads;
    let retryProof;
    let idempotency;
    let servedBeforeRetryProjection;
    let servedAfterRetryProjection;
    try {
      restoredReads = await restoredUiReads({ commonCapture, completedRun: {
        runId: blockerResult.capture.blockerRun.runId, agentId: blockerResult.capture.blockerRun.agentId },
        queuedRun: queue, reportReceipt, restoreResult, observerPool: restoredPool });
      const restoredBaseline = restoreResult.observations?.afterRetention;
      demand(restoredBaseline?.observerIdentity?.databaseName === restoreResult.restoreDatabaseName &&
        restoredBaseline.observerIdentity.databaseRole === 'oid_observer' && restoredBaseline.observerIdentity.transactionReadOnly === 'on',
      'combined_restore_baseline_observer_missing');
      const servedBeforeRetry = await provider.restoreAdapters.observeReadOnly({ databaseName: restoreResult.restoreDatabaseName,
        privateDataDir: restoreResult.privateDataDir, closureStatePath: restoreResult.closureStatePath });
      retryProof = await retryOriginalOperations({ commonCapture, completedRun: {
        recovery: completedCredential, blocker: blockerRetryMaterial.blocker, queue: blockerRetryMaterial.queue,
        redemptionPayload: blockerRetryMaterial.redemptionPayload, redemption: blockerRetryMaterial.redemption }, reportReceipt });
      const servedAfterRetry = await provider.restoreAdapters.observeReadOnly({ databaseName: restoreResult.restoreDatabaseName,
        privateDataDir: restoreResult.privateDataDir, closureStatePath: restoreResult.closureStatePath });
      servedBeforeRetryProjection = projectObserverSnapshot(servedBeforeRetry);
      servedAfterRetryProjection = projectObserverSnapshot(servedAfterRetry);
      idempotency = provider.verifyCombinedRestoreRetryProof({ restoredBaseline, before: servedBeforeRetry,
        after: servedAfterRetry, retryProof: { ...retryProof, receiptBindings: checkpoint.operationBindings,
          completedRunIds: sourceIds.completedRunIds, queuedInterruptedUnknownRunIds: sourceIds.queuedInterruptedUnknownRunIds,
          noNewGrantOrLedgerEffects: servedBeforeRetry.financialStateSha256 === servedAfterRetry.financialStateSha256,
          noNewRunTaskOrActionEffects: servedBeforeRetry.benchmarkStateSha256 === servedAfterRetry.benchmarkStateSha256 },
        operationBindings: checkpoint.operationBindings, originalIds: sourceIds, retentionExpired: false });
    } finally { await restoredPool.end(); }
    demand(restoredReads && retryProof && idempotency, 'combined_normal_restore_verification_incomplete');

    // The second clone alone gets synthetic historical closure authority. Source DB and
    // authoritative closure bytes remain unchanged; cleanup runs before API exposure.
    await commonCapture.stopApi();
    restoredApiStarted = false;
    const sourceClosurePath = commonCapture.reportCaptureIsolation?.closureStatePath;
    demand(isAbsolute(sourceClosurePath ?? ''), 'combined_source_closure_path_missing');
    const sourceClosureBytesBefore = await readFile(sourceClosurePath);
    const sourceClosure = parseJson(sourceClosureBytesBefore.toString('utf8'), 'combined_source_closure_json_invalid');
    demand(sourceClosure?.schemaVersion === 'beta-report-closure-state/v1' &&
      typeof sourceClosure.betaEndedAt === 'string' && HASH.test(sourceClosure.sourceEvidenceSha256 ?? ''),
    'combined_authoritative_source_closure_invalid');
    const databaseNow = await provider.getDatabaseNow();
    const syntheticBetaEndedAt = new Date(Date.parse(databaseNow) - 31 * 86_400_000 - 60_000).toISOString();
    const expiredRestoreResult = await provider.restoreCheckpoint({ retentionFixture: {
      kind: 'synthetic_historical_clone_31d', betaEndedAt: syntheticBetaEndedAt,
      sourceEvidenceSha256: sourceClosure.sourceEvidenceSha256,
    } });
    demand(expiredRestoreResult?.status === 'verified_unserved' && expiredRestoreResult.writesMayBeEnabled === false &&
      expiredRestoreResult.retention?.expired === true && expiredRestoreResult.retention.cloneCleanup?.status === 'complete' &&
      expiredRestoreResult.retention.syntheticHistoricalClosureFixture?.kind === 'synthetic_historical_clone_31d' &&
      expiredRestoreResult.retention.syntheticHistoricalClosureFixture.scope === 'restored_clone_only_synthetic_history',
    'combined_expired_clone_cleanup_not_verified');
    const expiredBaseline = expiredRestoreResult.observations?.afterRetention;
    demand(expiredBaseline?.observerIdentity?.databaseName === expiredRestoreResult.restoreDatabaseName &&
      expiredBaseline.observerIdentity.databaseRole === 'oid_observer' && expiredBaseline.observerIdentity.transactionReadOnly === 'on' &&
      expiredBaseline.reportCount === 0 && expiredBaseline.uploadCount === 0 && expiredBaseline.imageFiles.length === 0 &&
      expiredBaseline.reportDeletionReceipts.every((receipt) => receipt.status === 'complete') &&
      expiredRestoreResult.retention.cloneCleanup.financialStateBeforeSha256 === expiredRestoreResult.retention.cloneCleanup.financialStateAfterSha256 &&
      expiredRestoreResult.retention.cloneCleanup.benchmarkStateBeforeSha256 === expiredRestoreResult.retention.cloneCleanup.benchmarkStateAfterSha256,
    'combined_expired_clone_observer_or_nonreport_preservation_invalid');
    const expiredDatabaseUrl = expiredRestoreResult.takeRestoredDatabaseUrl();
    const expiredSecrets = expiredRestoreResult.takeRuntimeSecrets();
    await commonCapture.startRestoredApi({ databaseUrl: expiredDatabaseUrl, privateDataDir: expiredRestoreResult.privateDataDir,
      closureStatePath: expiredRestoreResult.closureStatePath, captureIsolationRoot: expiredRestoreResult.captureIsolationRoot,
      recoveredSecrets: expiredSecrets });
    restoredApiStarted = true;
    for (const key of Object.keys(expiredSecrets)) expiredSecrets[key] = '';
    const sourceClosureBytesAfterCloneRestore = await readFile(sourceClosurePath);
    demand(sourceClosureBytesBefore.equals(sourceClosureBytesAfterCloneRestore), 'combined_source_authoritative_closure_changed');
    const expiredObserverPool = new Pool({ connectionString: withDatabase(commonCapture.observerDatabaseUrl,
      expiredRestoreResult.restoreDatabaseName), max: 2, application_name: 'bpc-combined-expired-clone-observer' });
    let expiredAccess;
    let expiredRetryProof;
    let expiredIdempotency;
    let expiredBeforeRetryProjection;
    let expiredAfterRetryProjection;
    try {
      expiredAccess = await verifyExpiredReportAccess({ commonCapture, reportReceipt });
      const beforeExpiredRetries = await provider.restoreAdapters.observeReadOnly({ databaseName: expiredRestoreResult.restoreDatabaseName,
        privateDataDir: expiredRestoreResult.privateDataDir, closureStatePath: expiredRestoreResult.closureStatePath });
      const retryProofForExpired = await retryOriginalOperations({ commonCapture, completedRun: {
        recovery: completedCredential, blocker: blockerRetryMaterial.blocker, queue: blockerRetryMaterial.queue,
        redemptionPayload: blockerRetryMaterial.redemptionPayload, redemption: blockerRetryMaterial.redemption },
        reportReceipt, retentionExpired: true });
      const afterExpiredRetries = await provider.restoreAdapters.observeReadOnly({ databaseName: expiredRestoreResult.restoreDatabaseName,
        privateDataDir: expiredRestoreResult.privateDataDir, closureStatePath: expiredRestoreResult.closureStatePath });
      expiredBeforeRetryProjection = projectObserverSnapshot(beforeExpiredRetries);
      expiredAfterRetryProjection = projectObserverSnapshot(afterExpiredRetries);
      expiredRetryProof = retryProofForExpired;
      expiredIdempotency = provider.verifyCombinedRestoreRetryProof({ restoredBaseline: expiredBaseline,
        before: beforeExpiredRetries, after: afterExpiredRetries,
        retryProof: { ...retryProofForExpired, receiptBindings: checkpoint.operationBindings,
          completedRunIds: sourceIds.completedRunIds, queuedInterruptedUnknownRunIds: sourceIds.queuedInterruptedUnknownRunIds,
          noNewGrantOrLedgerEffects: beforeExpiredRetries.financialStateSha256 === afterExpiredRetries.financialStateSha256,
          noNewRunTaskOrActionEffects: beforeExpiredRetries.benchmarkStateSha256 === afterExpiredRetries.benchmarkStateSha256 },
        operationBindings: checkpoint.operationBindings, originalIds: sourceIds, retentionExpired: true });
    } finally { await expiredObserverPool.end(); }
    demand(expiredAccess && expiredRetryProof && expiredIdempotency, 'combined_expired_clone_access_or_retry_proof_missing');
    const sourceClosureBytesAtEnd = await readFile(sourceClosurePath);
    demand(sourceClosureBytesBefore.equals(sourceClosureBytesAtEnd), 'combined_source_closure_changed_during_expired_clone');
    await provider.checkpointAdapters.assertQuiescent({ databaseName: expectedDatabase });
    const sourceAfterRestore = await provider.checkpointAdapters.observeReadOnly({
      databaseName: expectedDatabase, boundaryId: `combined-after-restores-${commonCapture.runId}`,
    });
    const sourceAfterRestoreProof = verifyPostRestoreSourceStability({ checkpointSourceAfter: checkpoint.source.after,
      afterRestore: sourceAfterRestore, sourceDatabase: expectedDatabase });
    const sourceOperationsAfterRestore = await observeBefRecoveryOperations({
      committedActionRecovery: recovery.cases.committedActionRecovery,
      recoveryDeadlineExhaustion: recovery.cases.recoveryDeadlineExhaustion,
    });
    demand(sourceOperationsAfterRestore.schemaVersion === 'bpc-restored-bef-operation-observation/v1' &&
      sourceOperationsAfterRestore.identity?.role === 'bef_observer' &&
      sourceOperationsAfterRestore.identity?.databaseName === 'bef' &&
      sourceOperationsAfterRestore.identity?.transactionReadOnly === 'on' &&
      sourceOperationsAfterRestore.result.length === 2 && sourceOperationsAfterRestore.result.every((row) =>
        row.operations.length === 1 && HASH.test(row.operations[0].idempotencyKeySha256 ?? '') &&
        row.operations[0].status === 'settled' && row.operations[0].generationStatus === 'fenced'),
    'combined_source_operation_post_restore_readback_invalid');
    const checkpointSourceSnapshots = {
      before: projectObserverSnapshot(checkpoint.source?.before),
      after: projectObserverSnapshot(checkpoint.source?.after),
    };
    const result = { schemaVersion: 'bpc-combined-restore-runtime-observation/v1', scenarioId: 'BPC-SC-022',
      status: 'verified', localStatus: 'observed_partial',
      boundary: 'isolated_local_owner_admin_ui_postgres_private_images_host_sealed_checkpoint_and_two_fresh_restore_clones',
      sourceDatabase: expectedDatabase, recovery, reportCases: { localBoundary: reportCases.localBoundary,
        selectedScenarios: ['BPC-SC-018', 'BPC-SC-026'], originalReportId: reportReceipt.reportId,
        originalReportOperationIdSha256: sha256(Buffer.from(reportReceipt.operationId)), reportId: reportReceipt.reportId,
        reportOperationIdSha256: sha256(Buffer.from(reportReceipt.operationId)), linkedRunId: completedCredential.runId,
        linkedActionId: completedActionId, sourceStatus: reportReceipt.sourceStatus, sourceRevision: reportReceipt.sourceRevision,
        imageFilesVerified: restoredReads.observer.uploads },
      queueAndPause: { blockerRun: blockerResult.capture.blockerRun, queuedRunId: queue.runId,
        pauseRevision: paused.after.control.revision, pauseOperationId: paused.after.control.operation_id,
        completedWorkerRun: workerRun, pausedQueueObserver: pausedQueue },
      checkpoint: { status: checkpoint.status, checkpointId: checkpoint.checkpointId,
        inventorySha256: checkpoint.inventorySha256, databaseTotalsSha256: checkpoint.inventory.databaseTotalsSha256,
        operationBindings: checkpoint.operationBindings, originalIds: sourceIds,
        sourceStable: checkpoint.source?.after?.databaseTotalsSha256 === checkpoint.source?.before?.databaseTotalsSha256,
        sourceStableAfterRestore: sourceAfterRestoreProof.status === 'verified',
        sourceSnapshots: { ...checkpointSourceSnapshots, afterRestore: projectObserverSnapshot(sourceAfterRestore) },
        sourceAfterRestoreProof,
        sourceObserverEvidence: { observer: sourceObservation.observer, runCount: sourceObservation.runs.length,
          verifiedEvidenceFileCount: sourceObservation.verifiedEvidenceFiles.length,
          observationFile: { path: sourceObservationFile.relativePath, sha256: sourceObservationFile.sha256 } },
        verifiedOfficialEvidenceFiles: verifiedEvidenceFiles, writesMayBeEnabled: false },
      restore: projectRestore(restoreResult), restoredUi: restoredReads, retries: { ...retryProof,
        snapshots: { before: servedBeforeRetryProjection, after: servedAfterRetryProjection }, proof: idempotency },
      sourceOperationsAfterRestore,
      retentionExpiry: { status: 'verified_local_synthetic_historical_clone', boundary: 'synthetic_31_day_closure_in_second_restored_clone_only',
        syntheticHistoricalClosureUsed: true, sourceClosureUnchanged: true,
        sourceEvidenceSha256: sourceClosure.sourceEvidenceSha256, cloneBetaEndedAt: syntheticBetaEndedAt,
        cloneRestore: { status: expiredRestoreResult.status, checkpointId: expiredRestoreResult.checkpointId,
          restoreDatabaseName: expiredRestoreResult.restoreDatabaseName,
          checkpoint: { databaseDumpSha256: expiredRestoreResult.checkpoint.databaseDumpSha256 },
          creationReceipt: expiredRestoreResult.creationReceipt, restoreReceipt: expiredRestoreResult.restoreReceipt,
          writesMayBeEnabled: expiredRestoreResult.writesMayBeEnabled,
          targetHostAcceptance: expiredRestoreResult.targetHostAcceptance },
        cleanup: expiredRestoreResult.retention.cloneCleanup, cloneObservation: {
          databaseName: expiredRestoreResult.restoreDatabaseName, reportCount: expiredBaseline.reportCount,
          uploadCount: expiredBaseline.uploadCount, imageFileCount: expiredBaseline.imageFiles.length,
          deletionReceiptCount: expiredBaseline.reportDeletionReceipts.length,
          deletionReceiptsComplete: expiredBaseline.reportDeletionReceipts.every((receipt) => receipt.status === 'complete'),
          financialStateSha256: expiredBaseline.financialStateSha256,
          benchmarkStateSha256: expiredBaseline.benchmarkStateSha256 },
        accessDenial: expiredAccess, safeRetry: { ...expiredRetryProof,
          snapshots: { before: expiredBeforeRetryProjection, after: expiredAfterRetryProjection }, proof: expiredIdempotency },
        expiredContentAccessed: false, actualThirtyDayPassage: 'not_claimed' },
      claims: { exactSourceOperationsRetried: true, sourceWritesResubmitted: false,
        bonusGrantOrLedgerChanged: false, taskOrActionEffectsChanged: false, imageBytesMatchedDatabaseAndPrivateFile: true,
        targetHostAcceptance: 'not_run', externalOperatorRecovery: false, failureDomain: 'same_host' },
      unproven: ['actual_30_day_wall_clock_passage', 'external_host_failure_domain',
        'native_clients_on_restored_host', 'external_operator_dpapi_key_custody'] };
    assertSecretFree(result, 'beta-combined-restore-result');
    return result;
  } finally {
    if (completedCredential) completedCredential.agentBearer = '';
    if (blockerRetryMaterial?.blocker) blockerRetryMaterial.blocker.agentBearer = '';
    if (blockerRetryMaterial?.redemptionPayload) {
      blockerRetryMaterial.redemptionPayload.code = '';
      blockerRetryMaterial.redemptionPayload.operationId = '';
    }
    if (reportReceipt?.payload) reportReceipt.payload = null;
    if (restoredApiStarted) {
      // The runner owns the restored API lifecycle and will stop it during capture teardown.
    }
    if (!sourceObserverClosed) await ownerPool.end();
  }
}

async function runBetaRecoveryCasesCompletedRunState(pool, commonCapture, runId) {
  const snapshot = await readonly(pool, commonCapture.databaseIsolation.databaseName, async (client) => {
    const run = rows(await client.query(`SELECT id::text,status,terminal_reason FROM oid_benchmark_run WHERE id=$1::uuid`, [runId]));
    const evaluations = rows(await client.query(`SELECT task_index,task_id,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=$1::uuid ORDER BY task_index`, [runId])).map((row) => {
      let result = row.result_json;
      if (typeof result === 'string') { try { result = JSON.parse(result); } catch { result = null; } }
      return { taskIndex: row.task_index, taskId: row.task_id, resultHash: row.result_hash,
        evaluatorSourceHash: row.evaluator_source_hash, outcomeStatus: result?.status ?? null,
        outcome: result?.outcome ?? null, credit: result?.credit ?? null,
        mandatoryViolationPresent: result && Object.hasOwn(result, 'mandatoryViolation')
          ? result.mandatoryViolation !== null : null };
    });
    return { run: run[0] ?? null, evaluations };
  });
  return { identity: snapshot.identity, status: snapshot.value.run?.status ?? null,
    terminalReason: snapshot.value.run?.terminal_reason ?? null, evaluations: snapshot.value.evaluations };
}
