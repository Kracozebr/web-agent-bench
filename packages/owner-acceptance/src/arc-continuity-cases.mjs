import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { assertSecretFree } from './evidence.mjs';
import { runGenuineS1OwnerCase } from './genuine-s1-cases.mjs';
import { createArcTracingFetch } from './arc-http-trace.mjs';

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const parse = (value) => typeof value === 'string' ? JSON.parse(value) : value;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function requireFact(condition, code) { if (!condition) throw Object.assign(new Error(code), { code }); }

async function executeContinuity(ctx) {
  const proof = { schemaVersion: 'arc-continuity-physical-capture/v1', status: 'running',
    boundary: 'browser_owner_ui_real_mcp_worker_readonly_owner_bef_rpc', ownerId: ctx.ownerId,
    agentId: ctx.agentId, intentId: ctx.intentId, selectedTaskIds: ctx.taskIds, profile: ctx.continuityCase,
    observerClient: { implementation: 'mcp_sdk_reference_not_native_codex', wireName: 'arc-reference-sdk',
      wireVersion: '2.4.0', protocolVersion: '2026-07-28' },
    quotePriceUnits: ctx.quotePriceUnits, database: ctx.database, handoff: null,
    mcp: [], http: [ctx.launchIntentHttp], snapshots: [], sourceProofs: [] };
  const progress = () => ctx.captureProgress(structuredClone(proof));
  if (ctx.continuityCase === 'native_handoff') {
    await ctx.ownerPage.context().grantPermissions(['clipboard-read', 'clipboard-write'],
      { origin: new URL(ctx.publicOrigin).origin });
  }
  const handoff = ctx.ownerPage.getByTestId('run-intent-handoff-text-' + ctx.intentId);
  const visible = await handoff.innerText();
  const copyButton = ctx.ownerPage.getByTestId('run-intent-handoff-' + ctx.intentId);
  await copyButton.click();
  const copyUntil = Date.now() + 5000;
  let copyState = '';
  while (Date.now() < copyUntil) {
    copyState = await copyButton.innerText();
    if (copyState.includes('Copied safe handoff') ||
      (await ctx.ownerPage.getByTestId('run-intents-status').innerText()).includes('Clipboard access is unavailable')) break;
    await sleep(50);
  }
  let clipboard = null;
  if (copyState.includes('Copied safe handoff')) {
    try { clipboard = await ctx.ownerPage.evaluate(() => navigator.clipboard.readText()); } catch { /* Visible safe fallback is also a real rendered handoff. */ }
  }
  requireFact(visible.includes(ctx.intentId) && visible.includes('identity.preflight') &&
    visible.includes('runs.accept_launch_intent') && visible.includes('runs.current_task') &&
    visible.includes('runs.task_action_status') && visible.includes('runs.finish_task'), 'arc_handoff_contract_missing');
  if (clipboard !== null) assert.equal(clipboard, visible, 'clipboard must exactly match rendered handoff');
  if (ctx.continuityCase === 'native_handoff') requireFact(clipboard === visible,
    'arc_native_actual_clipboard_unavailable_or_mismatched');
  proof.handoff = { clicked: true, visible, clipboard, copyState, observedAt: new Date().toISOString(),
    url: ctx.ownerPage.url(), intentSnapshot: ctx.launchIntent.database };
  progress();
  let lastCallAt = 0;
  const tracing = createArcTracingFetch({ onRecord: (record) => {
    assertSecretFree(record, 'arc-mcp-http');
    if (!proof.http.includes(record)) proof.http.push(record);
    progress();
  } });
  const client = new Client({ name: 'arc-reference-sdk', version: '2.4.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  const transport = new StreamableHTTPClientTransport(new URL('/api/agent/mcp', ctx.publicOrigin), {
    requestInit: { headers: { authorization: 'Bearer ' + ctx.agentBearer, origin: new URL(ctx.publicOrigin).origin } },
    fetch: tracing.fetch, onInsufficientScope: 'throw' });
  let phase = 'mcp_connect';
  async function call(name, args, allowError = false) {
    await sleep(Math.max(0, 2100 - (Date.now() - lastCallAt)));
    lastCallAt = Date.now();
    const startedAt = new Date().toISOString();
    phase = name;
    const result = await client.callTool({ name, arguments: args });
    const body = result.structuredContent ?? parse(result.content?.find((item) => item.type === 'text')?.text ?? '{}');
    const record = { name, args, startedAt, finishedAt: new Date().toISOString(), isError: result.isError === true, body };
    assertSecretFree(record, 'arc-mcp-tool');
    proof.mcp.push(record); progress();
    requireFact(allowError || (!record.isError && !body.error), 'arc_mcp_' + (body.error?.code ?? 'tool_error'));
    return body;
  }
  async function snapshot(label) {
    const value = { label, observedAt: new Date().toISOString(), snapshot: await ctx.readSnapshot(proof.runId),
      completion: await ctx.readCompletion(proof.runId) };
    proof.snapshots.push(value); progress(); return value;
  }
  async function currentUntil(predicate, timeoutMs = 240_000) {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      const value = await call('runs.current_task', { runId: proof.runId });
      requireFact(value.run?.runId === proof.runId && typeof value.run.terminal === 'boolean' &&
        typeof value.state === 'string', 'arc_run_status_missing');
      if (predicate(value)) return value;
      requireFact(value.run.terminal === false, 'arc_premature_terminal');
      await sleep(Math.max(1000, value.retryAfterMs ?? 1000));
    }
    throw Object.assign(new Error('arc_current_task_timeout'), { code: 'arc_current_task_timeout' });
  }
  async function action(task, command) {
    const admitted = await call('runs.task_action', { runId: proof.runId, taskIndex: task.taskIndex,
      operationId: randomUUID(), command });
    requireFact(admitted.admitted === true && UUID.test(admitted.actionId ?? ''), 'arc_action_not_admitted');
    const until = Date.now() + 120_000;
    while (Date.now() < until) {
      const receipt = await call('runs.task_action_status', { runId: proof.runId, actionId: admitted.actionId });
      requireFact(receipt.runId === proof.runId && receipt.actionId === admitted.actionId, 'arc_action_receipt_identity');
      if (receipt.status === 'observed') return { ...receipt, actionId: admitted.actionId };
      requireFact(receipt.status === 'pending', 'arc_action_uncertain_or_rejected');
    }
    throw Object.assign(new Error('arc_action_timeout'), { code: 'arc_action_timeout' });
  }
  async function paidComponent(task, component, constraints = {}, retrieve = true) {
    const inspected = await action(task, { kind: 'inspect_offer', resourceId: component.resourceId,
      ...(constraints.offerId ? { offerId: constraints.offerId } : {}) });
    const resource = inspected.toolResponse;
    requireFact(resource?.freeInspection === true && resource.deliveryState === 'not_delivered' &&
      resource.resourceId === component.resourceId, 'arc_public_offer_read_invalid');
    const selection = { ...constraints, resource, assets: task.execution.assets, sourceIds: component.sourceIds };
    const offer = constraints.offerId ? resource.offers?.find((item) => item.id === constraints.offerId &&
      ctx.offerTermsMatch(item, selection)) : ctx.selectPublicOffer(resource, selection);
    requireFact(offer && /^[1-9][0-9]*$/.test(offer.payment?.amount ?? ''), 'arc_public_offer_unavailable');
    const payment = await action(task, { kind: 'pay', resourceId: component.resourceId, offerId: offer.id,
      offerReadActionId: inspected.actionId });
    requireFact(payment.toolResponse?.status === 'payment_confirmed' && payment.toolResponse.payment?.receiptStatus === 'success' &&
      payment.toolResponse.payment.amount === offer.payment.amount && /^0x[0-9a-f]{64}$/i.test(payment.transactionHash ?? ''),
    'arc_payment_not_confirmed');
    if (retrieve) {
      const delivered = await action(task, { kind: 'retrieve', payActionId: payment.actionId });
      const body = delivered.toolResponse;
      requireFact(body?.resourceId === component.resourceId && body.contentHash === resource.resourceSha256 &&
        typeof body.contentBytes === 'string' && hash(Buffer.from(body.contentBytes, 'base64')) === resource.resourceSha256,
      'arc_delivery_hash_mismatch');
    }
    return { paymentActionId: payment.actionId, amountUnits: offer.payment.amount, resourceId: component.resourceId };
  }
  try {
    if (ctx.continuityCase === 'native_handoff') {
      requireFact(typeof ctx.onArcNativeIntentReady === 'function', 'arc_native_callback_required');
      proof.native = await ctx.onArcNativeIntentReady({ agentBearer: ctx.agentBearer, agentId: ctx.agentId,
        intentId: ctx.intentId, handoffPrompt: visible, publicOrigin: ctx.publicOrigin, ownerPage: ctx.ownerPage,
        ownerId: ctx.ownerId, taskIds: ctx.taskIds, quotePriceUnits: ctx.quotePriceUnits,
        database: ctx.database, readonlyQuery: ctx.readonlyQuery });
      assertSecretFree(proof.native, 'arc-native-result');
      const intents = await ctx.readonlyQuery('SELECT run_id::text,status FROM oid_run_launch_intent WHERE id=$1 AND owner_id=$2 AND agent_id=$3',
        [ctx.intentId, ctx.ownerId, ctx.agentId]);
      requireFact(intents.length === 1 && intents[0].status === 'accepted' && UUID.test(intents[0].run_id ?? ''),
        'arc_native_intent_not_accepted');
      proof.runId = intents[0].run_id; progress();
      await client.connect(transport);
      proof.terminal = await currentUntil((value) => value.run.terminal === true);
      requireFact(proof.terminal.run.status === 'completed' && proof.terminal.task === null, 'arc_native_run_not_completed');
      const final = await snapshot('run_completed');
      requireFact(final.completion.evaluations.length === 3 && final.completion.evaluations.every((row, index) =>
        row.task_index === index && row.task_id === ctx.taskIds[index] && row.result_status === 'known' &&
        row.outcome === 'passed' && row.credit?.numerator === '1' && row.credit.denominator === '1'),
      'arc_native_all_tasks_not_known_passed');
      await collectFinalProof(ctx, proof, final);
      proof.status = 'verified'; progress(); return proof;
    }
    await client.connect(transport);
    const preflight = await call('identity.preflight', { agentId: ctx.agentId, operationId: randomUUID() });
    requireFact(preflight.status === 'allowed', 'arc_preflight_denied');
    proof.acceptOperationId = randomUUID();
    const accepted = await call('runs.accept_launch_intent', { intentId: ctx.intentId, operationId: proof.acceptOperationId });
    proof.runId = accepted.run?.id ?? accepted.run?.runId ?? null;
    requireFact(UUID.test(proof.runId ?? ''), 'arc_run_admission_missing'); progress();
    await snapshot('accepted');
    const first = await currentUntil((value) => value.task?.taskId === 'M1');
    const m1 = first.task;
    requireFact(m1.taskIndex === 0 && m1.participantToolProtocol === 'separate_payment_delivery_v2' &&
      Date.parse(m1.deadlineAt) > Date.now(), 'arc_m1_disclosure_invalid');
    proof.m1OriginalDeadline = m1.deadlineAt;
    await action(m1, { kind: 'inspect_catalog' });
    proof.m1Payment = await paidComponent(m1, m1.conditions.component, {
      offerId: m1.conditions.paymentScope.offerId, network: m1.conditions.paymentScope.network,
      recipient: m1.conditions.paymentScope.recipient, assetId: m1.conditions.paymentScope.assetId,
      scheme: m1.conditions.paymentScope.scheme }, false);
    const paid = await snapshot('m1_paid_before_original_deadline');
    requireFact(paid.snapshot.actions.filter((row) => row.taskIndex === 0).length === 3, 'arc_m1_action_prefix_invalid');
    // AICODE-NOTE: Wait for the original platform deadline; never rewrite clocks, task rows, receipts or grades.
    while (Date.now() <= Date.parse(m1.deadlineAt) + 100) {
      await call('runs.current_task', { runId: proof.runId });
      await sleep(Math.min(2500, Math.max(1, Date.parse(m1.deadlineAt) + 101 - Date.now())));
    }
    proof.lateRetrieve = await call('runs.task_action', { runId: proof.runId, taskIndex: 0,
      operationId: randomUUID(), command: { kind: 'retrieve', payActionId: proof.m1Payment.paymentActionId } }, true);
    requireFact(proof.lateRetrieve.admitted === false ||
      ['TASK_CLOSED', 'TASK_NOT_ACTIVE'].includes(proof.lateRetrieve.error?.code), 'arc_late_retrieve_was_admitted');
    await call('runs.finish_task', { runId: proof.runId, taskIndex: 0, operationId: randomUUID() }, true);
    const next = await currentUntil((value) => value.task?.taskId === 'H1');
    requireFact(next.task.taskIndex === 1, 'arc_successor_index_invalid');
    const h1Start = await snapshot('m1_known_failed_h1_issued');
    const m1Grade = h1Start.completion.evaluations.find((row) => row.task_index === 0);
    requireFact(m1Grade?.result_status === 'known' && m1Grade.outcome === 'failed' &&
      m1Grade.credit?.numerator === '0' && m1Grade.credit.denominator === '1', 'arc_m1_known_zero_missing');
    requireFact(h1Start.snapshot.actions.filter((row) => row.taskIndex === 0).length === 3 &&
      new Date(h1Start.snapshot.tasks[0].deadline_at).toISOString() === new Date(m1.deadlineAt).toISOString(), 'arc_original_deadline_or_action_prefix_changed');
    const h1 = next.task;
    requireFact(Array.isArray(h1.conditions.requiredComponents) && h1.conditions.requiredComponents.length > 0,
      'arc_h1_disclosure_missing');
    proof.h1Payments = [];
    let spend = 0n;
    for (const component of h1.conditions.requiredComponents) {
      const paidComponentFact = await paidComponent(h1, component);
      spend += BigInt(paidComponentFact.amountUnits);
      requireFact(spend <= BigInt(h1.conditions.expenseBudgetUsdcUnits), 'arc_h1_expense_budget_exceeded');
      proof.h1Payments.push(paidComponentFact);
    }
    await call('runs.finish_task', { runId: proof.runId, taskIndex: 1, operationId: randomUUID() });
    proof.terminal = await currentUntil((value) => value.run.terminal === true);
    requireFact(proof.terminal.run.status === 'completed' && proof.terminal.task === null, 'arc_terminal_not_completed');
    const final = await snapshot('run_completed');
    requireFact(final.completion.run?.status === 'completed' && final.completion.runRefundCount === 0 &&
      final.completion.slots.length === 0 && final.completion.claims.length === 1 &&
      final.completion.claims[0].status === 'released', 'arc_completion_resources_or_refunds_invalid');
    const debits = final.completion.ledger.filter((row) => row.entry_type === 'debit');
    requireFact(debits.length === 1 && debits[0].amount_units === ctx.quotePriceUnits &&
      debits[0].operation_id === 'rundeb_' + proof.runId.replaceAll('-', ''), 'arc_quote_not_debited_exactly_once');
    const h1Grade = final.completion.evaluations.find((row) => row.task_index === 1);
    requireFact(h1Grade?.result_status === 'known' && h1Grade.outcome === 'passed' &&
      h1Grade.credit?.numerator === '1' && h1Grade.credit.denominator === '1', 'arc_h1_known_pass_missing');
    await collectFinalProof(ctx, proof, final);
    proof.status = 'verified'; progress();
    return proof;
  } catch (error) {
    proof.status = 'blocked';
    proof.blocker = { phase, errorName: typeof error?.name === 'string' && /^[A-Za-z0-9_]{1,80}$/.test(error.name)
      ? error.name : 'TransportError', errorCode: typeof error?.code === 'number' ? error.code
      : typeof error?.code === 'string' && /^[A-Za-z0-9_]{1,96}$/.test(error.code) ? error.code : null };
    await tracing.settle(); progress();
    throw Object.assign(new Error('arc_continuity_driver_failed'), { code: typeof error?.code === 'string' &&
      /^[A-Za-z0-9_]{1,96}$/.test(error.code) ? error.code : 'arc_mcp_transport_or_driver_failed' });
  } finally { await client.close().catch(() => undefined); await tracing.settle(); progress(); }
}

async function collectFinalProof(ctx, proof, final) {
    await ctx.ownerPage.goto('/runs?agentId=' + encodeURIComponent(ctx.agentId), { waitUntil: 'domcontentloaded' });
    const status = ctx.ownerPage.getByTestId('owner-run-status-' + proof.runId);
    await status.waitFor({ state: 'visible', timeout: 15_000 });
    requireFact((await status.innerText()).trim() === 'completed', 'arc_browser_terminal_status_missing');
    const feedbackResponse = ctx.ownerPage.waitForResponse((response) =>
      new URL(response.url()).pathname === '/api/owner/runs/' + proof.runId + '/results' && response.request().method() === 'GET');
    await ctx.ownerPage.getByTestId('run-feedback-load-' + proof.runId).click();
    const feedbackHttp = await feedbackResponse;
    const feedback = await feedbackHttp.json();
    requireFact(feedbackHttp.status() === 200 && feedback.status === 'available' && feedback.tasks.length === ctx.taskIds.length,
      'arc_browser_feedback_unavailable');
    const renderedTasks = [];
    for (const taskId of ctx.taskIds) renderedTasks.push({ taskId,
      text: await ctx.ownerPage.getByTestId('run-feedback-task-' + proof.runId + '-' + taskId).innerText() });
    proof.browserFinal = { url: ctx.ownerPage.url(), statusText: await status.innerText(), renderedTasks,
      feedbackHttp: { status: feedbackHttp.status(), body: feedback } };
    requireFact(final.completion.run?.status === 'completed' && final.completion.runRefundCount === 0 &&
      final.completion.slots.length === 0 && final.completion.claims.length === 1 &&
      final.completion.claims[0].status === 'released', 'arc_final_resources_or_refunds_invalid');
    const debits = final.completion.ledger.filter((row) => row.entry_type === 'debit');
    requireFact(debits.length === 1 && debits[0].amount_units === ctx.quotePriceUnits &&
      debits[0].operation_id === 'rundeb_' + proof.runId.replaceAll('-', ''), 'arc_final_debit_invalid');
    const sources = await ctx.readonlyQuery(`SELECT e.task_index,e.input_hash,e.result_hash,e.result_json,
      b.bundle_hash,b.bundle_json,l.fence_evidence FROM oid_run_task_evaluation e
      JOIN oid_run_task_observation_bundle b ON b.run_id=e.run_id AND b.task_index=e.task_index
      JOIN oid_task_preparation_intent i ON i.run_id=e.run_id AND i.task_index=e.task_index
      JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      WHERE e.run_id=$1 ORDER BY e.task_index`, [proof.runId]);
    requireFact(sources.length === ctx.taskIds.length, 'arc_sealed_sources_missing');
    for (const row of sources) {
      const bundle = parse(row.bundle_json), fence = parse(row.fence_evidence);
      const execution = final.snapshot.execution.find((entry) => entry.task_index === row.task_index);
      requireFact(execution && fence?.confirmed === true && fence.generationId === execution.generation_id &&
        fence.preparationId === execution.preparation_id && fence.leaseId === execution.lease_id &&
        bundle.execution.generationId === execution.generation_id, 'arc_exact_generation_fence_missing');
      const capture = bundle.observations.captureEvidence;
      requireFact(capture.path.startsWith('artifacts/runs/owner-identity-bef-task-coordinator/') &&
        !capture.path.split('/').includes('..'), 'arc_capture_path_invalid');
      const bytes = await readFile(resolve(ctx.repoRoot, capture.path));
      requireFact(hash(bytes) === capture.sha256, 'arc_capture_bytes_changed');
      const source = JSON.parse(bytes.toString('utf8'));
      const sourceFence = await ctx.readSourceFence(proof.runId, execution, row.task_index);
      requireFact(sourceFence.length === 1 && sourceFence[0].generation_status === 'fenced' &&
        sourceFence[0].preparation_status === 'fenced' && sourceFence[0].preparation_generation_id === execution.generation_id,
      'arc_source_fence_readback_missing');
      if (ctx.continuityCase === 'paid_without_retrieve' && row.task_index === 0) requireFact(bundle.observations.deliveries.length === 0 &&
        bundle.observations.payments.length === 1 &&
        bundle.observations.payments[0].deliveryRequestAbsence?.schemaVersion === 'bts-delivery-request-absence/v1' &&
        source.bef.after.deliveries.length === 0 && source.ownerActions.every((action) => action.actionKind !== 'retrieve'),
      'arc_authoritative_no_retrieval_proof_missing');
      proof.sourceProofs.push({ ...row, bundle_json: bundle, fence_evidence: fence,
        captureEvidence: capture, capturePacket: source, sourceFence });
    }
}

/** Executes the actual browser → MCP → worker continuity case; never injects grades or source facts. */
export async function runArcContinuityOwnerCase(input) {
  requireFact(input.automaticWorkerEvaluation === true, 'arc_real_worker_required');
  const native = input.continuityCase === 'native_handoff';
  return runGenuineS1OwnerCase({ ...input, continuityCase: native ? 'native_handoff' : 'paid_without_retrieve',
    continuityTaskIds: native ? ['S1', 'M1', 'H1'] : ['M1', 'H1'],
    taskId: 'M1', exactQuoteBonusFunding: true, bonusCodeFunding: true, bddProbes: false,
    onGenuineLaunchIntentReady: executeContinuity });
}
