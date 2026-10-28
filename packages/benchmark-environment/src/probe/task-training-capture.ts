/**
 * Fixed open-training reference profiles on an isolated local BEF fork.
 * Each task starts and fences its own generation; these captures are not BTS acceptance.
 */
import { apiPath } from './environment.js';
import { sanitizeValue } from './evidence.js';
import type { GenerationSession, ProbeContext } from './runner.js';
import { captureSelectedUsdcTransfer } from './task-transfer-capture.js';
import { captureM1SinglePurchase, captureS2ReadonlyOffer, readCaseDatabaseFacts, startFreshCaseGeneration } from './task-reference-case-drivers.js';
import { captureH2ExactPayoutReference, projectH1TwoComponentCandidate } from './task-reference-h1h2-drivers.js';
import { captureS4M3M4 } from './task-native-capture.js';
import { purchasePinnedResourceInSession } from './task-h3-capture.js';

const PROFILE = {
  schemaVersion: 'bts-open-training-reference-profile/v1',
  classification: 'local_fork_public_tool_reference_not_bts_acceptance',
  cases: [
    { taskId: 'S1', transferUsdcUnits: '200000' },
    { taskId: 'S2', resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amountUsdcUnits: '125000' },
    { taskId: 'S4', initialAllowanceUnits: '20000' },
    { taskId: 'M1', resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
    { taskId: 'M3', inputUsdcUnits: '200000', quote: 'public exact quote plus independent QuoterV2 at quote block' },
    { taskId: 'M4', inputUsdcUnits: '200000', approvedUsdcUnits: '400000', quote: 'public exact quote plus independent QuoterV2 at quote block' },
    { taskId: 'H1', purchases: [
      { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
      { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-extended', amountUsdcUnits: '250000' },
    ], requiredOperatingBudgetUsdcUnits: '700000' },
    { taskId: 'H2', payoutUsdcUnits: ['200000', '300000'] },
  ],
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assert(condition: unknown, code: string): asserts condition {
  if (!condition) throw new Error(code);
}

function profileBudget(candidate: Record<string, unknown>): string | null {
  return isRecord(candidate.budgetProfile) && typeof candidate.budgetProfile.budgetUsdcUnits === 'string'
    ? candidate.budgetProfile.budgetUsdcUnits : null;
}

function purchaseArtifactPath(purchase: Record<string, unknown>, key: string): string {
  const artifacts = isRecord(purchase.artifacts) ? purchase.artifacts : null;
  const path = artifacts?.[key];
  if (typeof path !== 'string' || path.length === 0) throw new Error('task_training_h1_purchase_artifact_path_missing');
  return path;
}

async function fenceGeneration(ctx: ProbeContext, session: Pick<GenerationSession, 'envId' | 'generationId'>, taskId: string): Promise<Record<string, unknown>> {
  const variantId = `bts_${taskId.toLowerCase()}_training_reference_capture`;
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-training-${taskId.toLowerCase()}-generation-fence`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/generations/${session.generationId}/fence`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  const body = isRecord(response.body) ? response.body : null;
  if (response.status !== 200 || body?.status !== 'fenced' || body?.signerErased !== true) {
    throw new Error(`task_training_${taskId.toLowerCase()}_generation_fence_failed_${response.status}`);
  }
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId,
    label: `task-training-${taskId.toLowerCase()}-generation-after-fence`,
  });
  if (snapshot.generation.length !== 1 || snapshot.generation[0]?.status !== 'fenced') {
    throw new Error(`task_training_${taskId.toLowerCase()}_generation_fence_not_persisted`);
  }
  return { status: 'fenced', signerErased: true, databaseGeneration: snapshot.generation[0] };
}

async function captureH1ExtendedOffer(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const startedAt = Date.now();
  const variantId = 'bts_h1_training_reference_capture';
  const session = await startFreshCaseGeneration(ctx, { caseId: 'h1', scenarioId: 'BEF-SC-009', variantId });
  const before = await readCaseDatabaseFacts(ctx, session, 'h1-training-database-before-purchases', variantId);
  if (before.operations.length !== 0 || before.payments.length !== 0 || before.deliveries.length !== 0) {
    throw new Error('task_training_h1_generation_not_clean');
  }
  const selections = [
    { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000', label: 'task-training-h1-component-1' },
    { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-extended', amountUsdcUnits: '250000', label: 'task-training-h1-component-2' },
  ] as const;
  const purchases = [] as Array<Awaited<ReturnType<typeof purchasePinnedResourceInSession>>>;
  for (const selection of selections) {
    purchases.push(await purchasePinnedResourceInSession(ctx, session, {
      resourceId: selection.resourceId, offerId: selection.offerId, variantId, label: selection.label,
    }));
  }
  const candidate = await projectH1TwoComponentCandidate(ctx, {
    catalogCapture: {
      environment: { envId: session.envId, generationId: session.generationId, payerAddress: session.payerAddress },
      purchases: purchases.map((purchase) => ({
        operationId: purchase.operationId, resourceId: purchase.resourceId, offerId: purchase.offerId,
        paymentTransactionHash: purchase.transactionHash, amountUnits: purchase.amountUnits,
        resourceSha256: purchase.resourceSha256, deliveredContentBytes: purchase.contentBytes,
        receiptStatus: '0x1', selectedResourcePersisted: true, selectedOfferPersisted: true, paymentAndDeliveryPersisted: true,
      })),
    },
    deliveryProjections: purchases.map((purchase) => ({
      operationId: purchase.operationId,
      projectionPath: purchaseArtifactPath(purchase, 'projectionPath'), rawContentPath: purchaseArtifactPath(purchase, 'contentPath'),
      projection: purchase.deliveryProjection.projection, component: purchase.deliveryProjection.component,
      contentHash: purchase.deliveryProjection.contentBytesSha256,
    })),
    elapsedMs: Date.now() - startedAt,
  });
  const observedExpense = isRecord(candidate.observedExpense) ? candidate.observedExpense : null;
  assert(candidate.requiredComponentCount === 2 && profileBudget(candidate) === '700000'
    && observedExpense?.serviceChargesUsdcUnits === '350000', 'task_training_h1_extended_offer_budget_profile_mismatch');
  const result = {
    schemaVersion: 'bts-h1-training-reference/v1',
    classification: 'local_fork_public_tool_reference_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, payerAddress: session.payerAddress.toLowerCase() },
    candidate,
    selectedOffers: purchases.map((purchase) => ({
      resourceId: purchase.resourceId, offerId: purchase.offerId, amountUsdcUnits: purchase.amountUnits,
      operationId: purchase.operationId, transactionHash: purchase.transactionHash,
      resourceSha256: purchase.resourceSha256, contentPath: purchaseArtifactPath(purchase, 'contentPath'),
      projectionPath: purchaseArtifactPath(purchase, 'projectionPath'),
    })),
  };
  await ctx.evidence.writeObservation('task-training/h1-case-candidate.json', 'task-training-h1-case-candidate', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId: purchases[1]!.operationId, variantId,
    result: sanitizeValue(result, ctx.secretValues),
  });
  return result;
}

export async function captureOpenTrainingReferences(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const outputs: Array<Record<string, unknown>> = [];
  const guardrails = ctx.runtime.manifest.guardrails;
  const withCaseDeadline = () => {
    const deadlineAt = Date.now() + guardrails.maxSwapScenarioSeconds * 1_000;
    ctx.transport.setDeadlineAt(deadlineAt);
    ctx.rpc.setDeadlineAt(deadlineAt);
    ctx.database.setDeadlineAt(deadlineAt);
  };
  const withFenceDeadline = () => {
    const deadlineAt = Date.now() + 30_000;
    ctx.transport.setDeadlineAt(deadlineAt);
    ctx.rpc.setDeadlineAt(deadlineAt);
    ctx.database.setDeadlineAt(deadlineAt);
  };
  const run = async (taskId: string, capture: () => Promise<Record<string, unknown>>): Promise<void> => {
    const previousGenerationId = ctx.primaryGeneration?.generationId ?? null;
    withCaseDeadline();
    let value: Record<string, unknown>;
    try {
      value = await capture();
    } catch (error) {
      const partialGeneration = ctx.primaryGeneration;
      if (partialGeneration && partialGeneration.generationId !== previousGenerationId) {
        withFenceDeadline();
        await fenceGeneration(ctx, partialGeneration, taskId).catch(() => undefined);
      }
      throw error;
    }
    const generation = ctx.primaryGeneration;
    if (!generation) throw new Error(`task_training_${taskId.toLowerCase()}_generation_missing`);
    const session = { envId: generation.envId, generationId: generation.generationId };
    withFenceDeadline();
    const generationFence = await fenceGeneration(ctx, session, taskId);
    outputs.push({ taskId, generation: { ...generation }, capture: value, generationFence });
  };

  await run('S1', async () => captureSelectedUsdcTransfer(ctx, '200000'));
  await run('S2', async () => captureS2ReadonlyOffer(ctx, {
    resourceId: 'bef-market-state-brief-v1', expectedOfferId: 'market-brief-standard',
  }));
  await run('S4', async () => captureS4M3M4(ctx, '100000', {
    tasks: ['S4'], s4InitialAllowanceUnits: '20000',
  }));
  await run('M1', async () => captureM1SinglePurchase(ctx, {
    resourceId: 'bef-resource-v1', offerId: 'canonical',
  }));
  await run('M3', async () => captureOneNativeTask(ctx, 'M3'));
  await run('M4', async () => captureOneNativeTask(ctx, 'M4'));
  await run('H1', async () => captureH1ExtendedOffer(ctx));
  await run('H2', async () => captureH2ExactPayoutReference(ctx, { payoutAmountUnits: ['200000', '300000'] }));

  return {
    ...PROFILE,
    status: 'captured',
    releaseReadiness: 'blocked',
    taskCount: outputs.length,
    captures: outputs,
  };
}

async function captureOneNativeTask(ctx: ProbeContext, taskId: 'M3' | 'M4'): Promise<Record<string, unknown>> {
  const result = await captureS4M3M4(ctx, '200000', {
    tasks: [taskId], usePublicExactQuote: true,
  });
  const captures = isRecord(result.captures) ? result.captures : null;
  const capture = isRecord(captures?.[taskId]) ? captures[taskId] : null;
  if (result.status !== 'captured' || !capture) throw new Error(`task_training_${taskId.toLowerCase()}_capture_missing`);
  return { ...capture, caseArtifact: isRecord(result.captureArtifacts) ? result.captureArtifacts[taskId] : null };
}
