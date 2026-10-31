import { randomUUID } from 'node:crypto';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { assertSecretFree } from './evidence.mjs';
import { createArcTracingFetch } from './arc-http-trace.mjs';
import { runGenuineS1OwnerCase } from './genuine-s1-cases.mjs';
import { publicActorResultFromMcpReceipt, s2PublicDisclosureGap, isKnownS2DisclosureGap } from './pdc-public-action-result.mjs';

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const parse = (value) => typeof value === 'string' ? JSON.parse(value) : value;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PAID = new Set(['M1','M2','H1','H3','U1']);
function need(condition, code) { if (!condition) throw Object.assign(new Error(code), { code }); }

async function executePdc(ctx) {
  const proof = { schemaVersion: 'paid-delivery-cutoff-physical-capture/v1', status: 'running',
    caseName: ctx.mode === 'ranked' ? 'ranked_all_paid_families' : 'training_h1_original_deadline', mode: ctx.mode,
    selectedTaskIds: ctx.taskIds, ownerId: ctx.ownerId, agentId: ctx.agentId, intentId: ctx.intentId,
    quotePriceUnits: ctx.quotePriceUnits, database: ctx.database, tasks: [], mcp: [], http: [ctx.launchIntentHttp],
    snapshots: [], sourceProofs: [], observerClient: { implementation: 'mcp_sdk_reference', name: 'pdc-reference-sdk',
      version: '2.4.0', protocolVersion: '2026-07-28' } };
  const progress = () => ctx.captureProgress(structuredClone(proof));
  const tracing = createArcTracingFetch({ onRecord: (record) => {
    assertSecretFree(record, 'pdc-http'); if (!proof.http.includes(record)) proof.http.push(record); progress();
  } });
  const client = new Client({ name: 'pdc-reference-sdk', version: '2.4.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  const transport = new StreamableHTTPClientTransport(new URL('/api/agent/mcp', ctx.publicOrigin), {
    requestInit: { headers: { authorization: 'Bearer ' + ctx.agentBearer, origin: new URL(ctx.publicOrigin).origin } },
    fetch: tracing.fetch, onInsufficientScope: 'throw' });
  let lastAt = 0, phase = 'mcp_connect';
  async function call(name, args, allowError = false) {
    phase = name; await sleep(Math.max(0, 2100 - (Date.now() - lastAt))); lastAt = Date.now();
    const startedAt = new Date().toISOString(), result = await client.callTool({ name, arguments: args });
    const body = result.structuredContent ?? parse(result.content?.find((item) => item.type === 'text')?.text ?? '{}');
    proof.mcp.push({ name, args, startedAt, finishedAt: new Date().toISOString(), isError: result.isError === true, body }); progress();
    need(allowError || (!result.isError && !body.error), 'pdc_mcp_' + (body.error?.code ?? 'tool_error'));
    return body;
  }
  async function snapshot(label) {
    const row = { label, observedAt: new Date().toISOString(), snapshot: await ctx.readSnapshot(proof.runId),
      completion: await ctx.readCompletion(proof.runId) };
    proof.snapshots.push(row); progress(); return row;
  }
  async function untilCurrent(predicate, timeoutMs = 240_000) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const current = await call('runs.current_task', { runId: proof.runId });
      need(current.run?.runId === proof.runId && typeof current.run.terminal === 'boolean' && typeof current.state === 'string',
        'pdc_explicit_run_status_missing');
      if (predicate(current)) return current;
      need(current.run.terminal === false, 'pdc_unexpected_terminal');
      await sleep(Math.max(1000, current.retryAfterMs ?? 1000));
    }
    throw Object.assign(new Error('pdc_current_task_timeout'), { code: 'pdc_current_task_timeout' });
  }
  async function action(task, command) {
    const admitted = await call('runs.task_action', { runId: proof.runId, taskIndex: task.taskIndex, operationId: randomUUID(), command });
    need(admitted.admitted === true && UUID.test(admitted.actionId ?? ''), 'pdc_action_not_admitted');
    const end = Date.now() + 120_000;
    while (Date.now() < end) {
      const receipt = await call('runs.task_action_status', { runId: proof.runId, actionId: admitted.actionId });
      need(receipt.actionId === admitted.actionId && receipt.runId === proof.runId, 'pdc_action_receipt_identity');
      if (receipt.status === 'observed') return receipt;
      need(receipt.status === 'pending', 'pdc_action_unknown_or_rejected');
    }
    throw Object.assign(new Error('pdc_action_timeout'), { code: 'pdc_action_timeout' });
  }
  async function purchase(task, component, constraints, retrieve) {
    const inspected = await action(task, { kind: 'inspect_offer', resourceId: component.resourceId,
      ...(constraints.offerId ? { offerId: constraints.offerId } : {}) });
    const resource = inspected.toolResponse;
    need(resource?.resourceId === component.resourceId && resource.freeInspection === true && resource.deliveryState === 'not_delivered',
      'pdc_public_resource_read_invalid');
    const selection = { ...constraints, sourceIds: component.sourceIds, resource, assets: task.execution.assets };
    const offer = constraints.offerId ? resource.offers?.find((item) => item.id === constraints.offerId && ctx.offerTermsMatch(item, selection))
      : ctx.selectPublicOffer(resource, selection);
    need(offer && /^[1-9][0-9]*$/.test(offer.payment?.amount ?? ''), 'pdc_canonical_offer_unavailable');
    const paid = await action(task, { kind: 'pay', resourceId: component.resourceId, offerId: offer.id, offerReadActionId: inspected.actionId });
    need(paid.toolResponse?.status === 'payment_confirmed' && paid.toolResponse.payment?.receiptStatus === 'success' &&
      paid.toolResponse.payment.amount === offer.payment.amount && UUID.test(paid.toolResponse.operationId ?? ''), 'pdc_payment_not_settled');
    if (retrieve) {
      const received = await action(task, { kind: 'retrieve', payActionId: paid.actionId });
      need(received.toolResponse?.resourceId === component.resourceId && received.toolResponse.contentHash === resource.resourceSha256,
        'pdc_delivered_resource_mismatch');
    }
    return { paymentActionId: paid.actionId, operationId: paid.toolResponse.operationId, resourceId: component.resourceId,
      amountUnits: offer.payment.amount, transactionHash: paid.transactionHash, retrieved: retrieve };
  }
  async function chooseMissingPayment(task, fact) {
    const c = task.conditions;
    if (task.taskId === 'M1') {
      const p = c.paymentScope;
      fact.expectedAbsencePayments.push(await purchase(task, c.component, { offerId: p.offerId,
        network: p.network, recipient: p.recipient, assetId: p.assetId, scheme: p.scheme }, false));
    } else if (task.taskId === 'M2') {
      const catalog = await action(task, { kind: 'inspect_catalog' });
      const selected = ctx.selectCatalogOffer(catalog.toolResponse, c.required, task.execution.assets);
      need(selected, 'pdc_public_m2_selection_missing');
      fact.expectedAbsencePayments.push(await purchase(task, { resourceId: selected.resourceId }, {
        offerId: selected.offerId, dataType: c.required.requiredDataType, assetId: c.required.assetId,
        network: c.required.network, recipient: c.required.recipient }, false));
    } else if (task.taskId === 'H1') {
      need(Array.isArray(c.requiredComponents) && c.requiredComponents.length > 1, 'pdc_h1_components_missing');
      fact.deliveredPayments = [];
      for (const component of c.requiredComponents.slice(0, -1)) fact.deliveredPayments.push(await purchase(task, component, {}, true));
      fact.expectedAbsencePayments.push(await purchase(task, c.requiredComponents.at(-1), {}, false));
    } else if (task.taskId === 'H3') fact.expectedAbsencePayments.push(await purchase(task, c.referenceComponent, {}, false));
    else {
      need(task.taskId === 'U1' && c.requiredComponents?.length > 0, 'pdc_u1_components_missing');
      fact.expectedAbsencePayments.push(await purchase(task, c.requiredComponents[0], {}, false));
    }
  }
  try {
    await client.connect(transport);
    const preflight = await call('identity.preflight', { agentId: ctx.agentId, operationId: randomUUID() });
    need(preflight.status === 'allowed', 'pdc_preflight_denied');
    proof.acceptOperationId = randomUUID();
    const accepted = await call('runs.accept_launch_intent', { intentId: ctx.intentId, operationId: proof.acceptOperationId });
    proof.runId = accepted.run?.id ?? accepted.run?.runId;
    need(UUID.test(proof.runId ?? ''), 'pdc_accepted_run_missing'); await snapshot('accepted');
    let current = await untilCurrent((value) => value.task?.taskIndex === 0);
    for (let index = 0; index < ctx.taskIds.length; index++) {
      const task = current.task;
      need(task?.taskId === ctx.taskIds[index] && task.taskIndex === index && task.mode === ctx.mode &&
        Date.parse(task.deadlineAt) > Date.now(), 'pdc_task_disclosure_binding');
      const fact = { taskIndex: index, taskId: task.taskId, issued: task, originalDeadline: task.deadlineAt, expectedAbsencePayments: [] };
      proof.tasks.push(fact); await snapshot('task_issued_' + index);
      const missing = PAID.has(task.taskId) && (ctx.mode === 'ranked' || task.taskId === 'H1');
      if (missing) await chooseMissingPayment(task, fact);
      else {
        const solved = await ctx.runPublicTask(task, async (command, expectsTransaction) => {
          const receipt = await action(task, command);
          if (task.taskId === 'S2' && command.kind === 'inspect_offer') fact.publicDisclosureGap = s2PublicDisclosureGap(task, receipt, {
            mcpRecordIndex: proof.mcp.length - 1, actionId: receipt.actionId, receiptRevision: receipt.receiptRevision,
            evidenceHash: receipt.evidenceHash, evidencePath: receipt.evidencePath });
          return publicActorResultFromMcpReceipt(receipt, command, expectsTransaction);
        });
        if (solved.answer) fact.answer = solved.answer;
      }
      if (ctx.mode === 'training' && task.taskId === 'H1') {
        while (Date.now() <= Date.parse(task.deadlineAt) + 100) {
          await call('runs.current_task', { runId: proof.runId });
          await sleep(Math.min(2500, Math.max(1, Date.parse(task.deadlineAt) + 101 - Date.now())));
        }
        fact.lateRetrieve = await call('runs.task_action', { runId: proof.runId, taskIndex: index, operationId: randomUUID(),
          command: { kind: 'retrieve', payActionId: fact.expectedAbsencePayments[0].paymentActionId } }, true);
        need(fact.lateRetrieve.admitted === false || ['TASK_CLOSED','TASK_NOT_ACTIVE','RUN_NOT_ACTIVE'].includes(fact.lateRetrieve.error?.code),
          'pdc_late_retrieval_admitted');
      }
      fact.finish = await call('runs.finish_task', { runId: proof.runId, taskIndex: index, operationId: randomUUID(),
        ...(fact.answer ? { answer: fact.answer } : {}) }, ctx.mode === 'training' && task.taskId === 'H1');
      // Always requery after finish; task:null is only a wait state until explicit terminal confirmation.
      current = await untilCurrent((value) => value.run.terminal === true || value.task?.taskIndex === index + 1);
      const closed = await snapshot('task_terminalized_' + index);
      const grade = closed.completion.evaluations.find((entry) => entry.task_index === index);
      need(grade?.result_status === 'known' && grade.task_id === task.taskId, 'pdc_task_result_unknown');
      fact.grade = grade;
      const original = closed.snapshot.tasks.find((entry) => entry.task_index === index);
      need(new Date(original.deadline_at).toISOString() === new Date(task.deadlineAt).toISOString(), 'pdc_original_clock_changed');
      if (!missing) need(grade.outcome === 'passed' && grade.credit?.numerator === '1' && grade.credit.denominator === '1' ||
        task.taskId === 'S2' && isKnownS2DisclosureGap(grade, fact.publicDisclosureGap),
        'pdc_public_reference_task_not_passed');
      if (index < ctx.taskIds.length - 1) need(current.run.terminal === false, 'pdc_run_ended_before_all_tasks');
    }
    proof.terminal = current;
    need(current.run.terminal === true && current.run.status === 'completed' && current.task === null, 'pdc_run_not_completed');
    const final = await snapshot('run_completed');
    await retainFinalSources(ctx, proof, final);
    proof.status = 'verified'; progress(); return proof;
  } catch (error) {
    proof.status = 'blocked'; proof.blocker = { phase, errorName: error?.name ?? 'Error',
      errorCode: typeof error?.code === 'number' ? error.code : typeof error?.code === 'string' ? error.code : null };
    await tracing.settle(); progress();
    throw Object.assign(new Error('pdc_driver_failed'), { code: typeof error?.code === 'string' && /^[A-Za-z0-9_]{1,96}$/.test(error.code)
      ? error.code : 'pdc_transport_or_driver_failed' });
  } finally { await client.close().catch(() => undefined); await tracing.settle(); progress(); }
}

async function retainFinalSources(ctx, proof, final) {
  const c = final.completion;
  need(c.run?.status === 'completed' && c.runRefundCount === 0 && c.slots.length === 0 && c.claims.length === 1 &&
    c.claims[0].status === 'released' && c.completionEvents.length === 1, 'pdc_terminal_financial_or_slot_state');
  const debits = c.ledger.filter((entry) => entry.entry_type === 'debit');
  need(debits.length === 1 && debits[0].amount_units === ctx.quotePriceUnits && debits[0].operation_id ===
    'rundeb_' + proof.runId.replaceAll('-', ''), 'pdc_once_only_quoted_debit');
  const rows = await ctx.readonlyQuery(`SELECT e.task_index,e.input_hash,e.result_hash,e.result_json,b.bundle_hash,b.bundle_json,l.fence_evidence
    FROM oid_run_task_evaluation e JOIN oid_run_task_observation_bundle b ON b.run_id=e.run_id AND b.task_index=e.task_index
    JOIN oid_task_preparation_intent i ON i.run_id=e.run_id AND i.task_index=e.task_index
    JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    WHERE e.run_id=$1 ORDER BY e.task_index`, [proof.runId]);
  need(rows.length === ctx.taskIds.length, 'pdc_sealed_task_set_missing');
  for (const row of rows) {
    const bundle = parse(row.bundle_json), fence = parse(row.fence_evidence);
    const execution = final.snapshot.execution.find((item) => item.task_index === row.task_index);
    need(fence?.confirmed === true && fence.generationId === execution.generation_id && fence.preparationId === execution.preparation_id &&
      fence.leaseId === execution.lease_id && bundle.execution.generationId === execution.generation_id, 'pdc_generation_fence_mismatch');
    const sourceFence = await ctx.readSourceFence(proof.runId, execution, row.task_index);
    need(sourceFence.length === 1 && sourceFence[0].generation_status === 'fenced' && sourceFence[0].preparation_status === 'fenced' &&
      sourceFence[0].preparation_generation_id === execution.generation_id, 'pdc_source_fence_not_confirmed');
    const captureEvidence = bundle.observations.captureEvidence;
    const capturePacket = JSON.parse((await ctx.readEvidence(captureEvidence)).bytes.toString('utf8'));
    const childCaptures = [];
    for (const child of Object.values(capturePacket.children ?? {})) childCaptures.push({ captureEvidence: child.evidence,
      capturePacket: JSON.parse((await ctx.readEvidence(child.evidence)).bytes.toString('utf8')) });
    for (const wanted of proof.tasks[row.task_index].expectedAbsencePayments) {
      const payment = bundle.observations.payments.find((item) => item.transactionHash?.toLowerCase() === wanted.transactionHash?.toLowerCase());
      need(payment?.deliveryRequestAbsence?.paymentActionSequence !== undefined &&
        payment.deliveryRequestAbsence.paymentAttemptId === payment.paymentAttemptId &&
        !bundle.observations.deliveries.some((item) => item.paymentAttemptId === payment.paymentAttemptId), 'pdc_expected_payment_absence_missing');
    }
    proof.sourceProofs.push({ ...row, bundle_json: bundle, fence_evidence: fence, captureEvidence, capturePacket, childCaptures, sourceFence });
  }
  await ctx.ownerPage.goto('/runs?agentId=' + encodeURIComponent(ctx.agentId), { waitUntil: 'domcontentloaded' });
  const status = ctx.ownerPage.getByTestId('owner-run-status-' + proof.runId); await status.waitFor({ state: 'visible', timeout: 15_000 });
  need((await status.innerText()).trim() === 'completed', 'pdc_owner_ui_completion_missing');
  const response = ctx.ownerPage.waitForResponse((item) => new URL(item.url()).pathname === '/api/owner/runs/' + proof.runId + '/results');
  await ctx.ownerPage.getByTestId('run-feedback-load-' + proof.runId).click();
  const http = await response, feedback = await http.json();
  need(http.status() === 200 && feedback.status === 'available' && feedback.tasks.length === ctx.taskIds.length, 'pdc_owner_feedback_missing');
  const renderedTasks = [];
  for (const taskId of ctx.taskIds) renderedTasks.push({ taskId, text: await ctx.ownerPage.getByTestId('run-feedback-task-' + proof.runId + '-' + taskId).innerText() });
  proof.browserFinal = { url: ctx.ownerPage.url(), statusText: await status.innerText(), renderedTasks, feedbackHttp: { status: http.status(), body: feedback } };
}

export async function runPaidDeliveryCutoffOwnerCase(input) {
  need(input.automaticWorkerEvaluation === true && ['training','ranked'].includes(input.pdcProfile), 'pdc_profile_or_worker_invalid');
  return runGenuineS1OwnerCase({ ...input, mode: input.pdcProfile, pdcCase: true, bddProbes: false,
    exactQuoteBonusFunding: true, bonusCodeFunding: true, primaryClientOnly: false,
    onGenuineLaunchIntentReady: executePdc });
}
