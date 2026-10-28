/** One ranked M2 local-fork reference using separate catalog, pay, and retrieve actions. */
import type { RuntimeManifest } from '../manifest.js';
import type { GenerationSession, ProbeContext } from './runner.js';
import type { DifficultyMode, DifficultyProfileSource } from './task-difficulty-v2-capture.js';
import { latestBlock, readCaseDatabaseFacts, readCaseState, startFreshCaseGeneration } from './task-reference-case-drivers.js';
import { canonicalSha256 } from './task-reference-cases.js';
import {
  minimumM2Offer,
  projectM2CatalogObjective,
  type CatalogOfferObservation,
  type CatalogObjectiveCandidate,
  type PublicCatalogProjection,
} from './task-reference-catalog-objectives.js';
import {
  inspectSplitCatalog,
  payAndRetrieveSplitResource,
  type SplitParticipantAction,
} from './task-split-resource-capture.js';

const PROFILE_ID = 'bts-task-difficulty-v2';
const UINT = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/i;

export type DifficultyV2M2Capture = {
  taskId: 'M2';
  mode: DifficultyMode;
  capture: Record<string, unknown>;
  session: GenerationSession;
  participantActions: SplitParticipantAction[];
  caseArtifact: { path: string; sha256: string };
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_difficulty_v2_m2_${label}_invalid`);
  return value;
}

export function validateM2DifficultyV2ProfileTask(source: DifficultyProfileSource, mode: DifficultyMode): void {
  const tasks = record(source.profile.tasks);
  const task = record(tasks?.M2);
  const plan = Array.isArray(task?.participantActionPlan) ? task.participantActionPlan : [];
  if (mode !== 'ranked' || task?.rankedOnly !== true || task.countedParticipantActions !== 3
    || JSON.stringify(plan) !== JSON.stringify(['inspect_catalog', 'pay:minimum-qualifying-offer', 'retrieve'])
    || task.selectionRule !== 'minimum_complete_advertised_price_among_pinned_qualifying_offers') {
    throw new Error('task_difficulty_v2_m2_profile_action_or_mode_invalid');
  }
}

/** Select only from the fully manifest-pinned projection of the actual public catalog response. */
export function selectM2DifficultyV2MinimumOffer(publicCatalog: PublicCatalogProjection): CatalogOfferObservation {
  const offers = publicCatalog.offers.filter((offer) => offer.dataType === 'market-state-brief');
  if (offers.length < 2 || new Set(offers.map((offer) => offer.offerId)).size !== offers.length
    || new Set(offers.map((offer) => offer.resourceId)).size !== 1
    || new Set(offers.map((offer) => offer.network)).size !== 1
    || new Set(offers.map((offer) => offer.assetId.toLowerCase())).size !== 1
    || new Set(offers.map((offer) => offer.recipient.toLowerCase())).size !== 1
    || offers.some((offer) => !UINT.test(offer.advertisedTotalPriceUsdcUnits))) {
    throw new Error('task_difficulty_v2_m2_qualifying_catalog_invalid');
  }
  if (new Set(offers.map((offer) => offer.advertisedTotalPriceUsdcUnits)).size < 2) {
    throw new Error('task_difficulty_v2_m2_qualifying_prices_not_distinct');
  }
  return offers.reduce((minimum, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits)
    < BigInt(minimum.advertisedTotalPriceUsdcUnits) ? offer : minimum);
}

function pinnedOffer(manifest: RuntimeManifest, selected: CatalogOfferObservation): {
  resourceSha256: string;
  amount: string;
  schema: string;
} {
  const resources = manifest.x402.catalog?.filter((resource) => resource.resourceId === selected.resourceId) ?? [];
  const resource = resources.length === 1 ? resources[0] : undefined;
  const offers = resource?.offers.filter((offer) => offer.id === selected.offerId) ?? [];
  const offer = offers.length === 1 ? offers[0] : undefined;
  if (!resource || !offer || resource.dataType !== 'market-state-brief'
    || offer.amount !== selected.advertisedTotalPriceUsdcUnits) {
    throw new Error('task_difficulty_v2_m2_selected_offer_manifest_mismatch');
  }
  return { resourceSha256: resource.resourceSha256, amount: offer.amount, schema: resource.schema };
}

function facilitatorAddress(ctx: ProbeContext): string {
  const services = record(ctx.capability.services);
  const facilitator = record(services?.facilitator);
  const address = requiredString(facilitator?.address, 'facilitator_address').toLowerCase();
  if (!ADDRESS.test(address)) throw new Error('task_difficulty_v2_m2_facilitator_address_invalid');
  return address;
}

function sessionProjection(session: GenerationSession): Record<string, string> {
  return {
    envId: session.envId,
    generationId: session.generationId,
    participantId: session.participantId,
    payerAddress: session.payerAddress.toLowerCase(),
  };
}

function assertBaseline(
  snapshot: Awaited<ReturnType<ProbeContext['database']['snapshot']>>,
  session: GenerationSession,
): void {
  const generation = snapshot.generation.length === 1 ? snapshot.generation[0]! : null;
  if (!generation || String(generation.generation_id).toLowerCase() !== session.generationId.toLowerCase()
    || String(generation.participant_id) !== session.participantId
    || String(generation.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || generation.status !== 'active' || snapshot.operations.length !== 0 || snapshot.payments.length !== 0
    || snapshot.deliveries.length !== 0 || snapshot.denials.length !== 0) {
    throw new Error('task_difficulty_v2_m2_generation_baseline_not_clean');
  }
}

async function readBoundaryState(
  ctx: ProbeContext,
  session: GenerationSession,
  variantId: string,
  suffix: 'initial' | 'final',
  operationId: string | null,
): Promise<Record<string, unknown>> {
  const block = await latestBlock(ctx, operationId, variantId, `task-difficulty-v2-m2-${suffix}-state`);
  const state = await readCaseState(ctx, {
    session, blockTag: block.tag, blockHash: block.hash, operationId, variantId,
    label: `task-difficulty-v2-m2-${suffix}-state`,
  });
  if (String(state.blockNumber) !== block.number || String(state.blockHash).toLowerCase() !== block.hash.toLowerCase()
    || String(state.payerAddress).toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error(`task_difficulty_v2_m2_${suffix}_state_cutoff_mismatch`);
  }
  return state;
}

function assertPaymentBoundaryStates(initial: Record<string, unknown>, final: Record<string, unknown>, amount: bigint): void {
  const value = (state: Record<string, unknown>, field: string): bigint => {
    const parsed = String(state[field] ?? '');
    if (!UINT.test(parsed)) throw new Error(`task_difficulty_v2_m2_state_${field}_invalid`);
    return BigInt(parsed);
  };
  if (value(initial, 'payerUsdcUnits') - value(final, 'payerUsdcUnits') !== amount
    || value(initial, 'payerNativeEthWei') !== value(final, 'payerNativeEthWei')
    || value(initial, 'payerWethUnits') !== value(final, 'payerWethUnits')
    || value(initial, 'usdcRouterAllowanceUnits') !== value(final, 'usdcRouterAllowanceUnits')
    || value(initial, 'wethRouterAllowanceUnits') !== value(final, 'wethRouterAllowanceUnits')) {
    throw new Error('task_difficulty_v2_m2_common_block_effect_mismatch');
  }
}

function assertObjectiveSelectedMinimum(
  objective: CatalogObjectiveCandidate,
  selected: CatalogOfferObservation,
): void {
  const minimum = minimumM2Offer(objective);
  if (minimum.offerId !== selected.offerId || minimum.resourceId !== selected.resourceId
    || minimum.advertisedTotalPriceUsdcUnits !== selected.advertisedTotalPriceUsdcUnits) {
    throw new Error('task_difficulty_v2_m2_paid_offer_not_minimum');
  }
}

/** Capture exactly one ranked M2 catalog selection followed by its actual pay and retrieve. */
export async function captureM2DifficultyV2Task(
  ctx: ProbeContext,
  mode: DifficultyMode,
  source: DifficultyProfileSource,
): Promise<DifficultyV2M2Capture> {
  validateM2DifficultyV2ProfileTask(source, mode);
  if (ctx.runtime.manifest.tools.participantProtocol !== 'separate_payment_delivery_v2') {
    throw new Error('task_difficulty_v2_participant_protocol_not_pinned');
  }
  const variantId = 'bts_m2_ranked_difficulty_v2_split_reference';
  const session = await startFreshCaseGeneration(ctx, { caseId: 'm2', scenarioId: 'BEF-SC-006', variantId });
  const baseline = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    variantId, label: `${variantId}-baseline` });
  assertBaseline(baseline, session);
  const initialState = await readBoundaryState(ctx, session, variantId, 'initial', null);
  const startedAt = Date.now();

  const read = await inspectSplitCatalog(ctx, session, { variantId, label: variantId });
  const publicCatalog = read.catalogProjection;
  if (read.kind !== 'catalog' || !publicCatalog) throw new Error('task_difficulty_v2_m2_catalog_projection_missing');
  const facilitator = facilitatorAddress(ctx);
  if (publicCatalog.facilitatorAddress.toLowerCase() !== facilitator) {
    throw new Error('task_difficulty_v2_m2_facilitator_read_mismatch');
  }
  const selected = selectM2DifficultyV2MinimumOffer(publicCatalog);
  const pin = pinnedOffer(ctx.runtime.manifest, selected);
  if (publicCatalog.resourceHashes[selected.resourceId]?.toLowerCase() !== pin.resourceSha256.toLowerCase()) {
    throw new Error('task_difficulty_v2_m2_selected_resource_hash_mismatch');
  }
  const accepted = read.offers.filter((offer) => offer.resourceId === selected.resourceId && offer.offerId === selected.offerId);
  if (accepted.length !== 1 || accepted[0]!.acceptedTerms.amount !== pin.amount
    || accepted[0]!.acceptedTerms.payTo.toLowerCase() !== facilitator) {
    throw new Error('task_difficulty_v2_m2_observed_offer_binding_mismatch');
  }

  const paid = await payAndRetrieveSplitResource(ctx, session,
    { resourceId: selected.resourceId, offerId: selected.offerId }, read, { variantId, label: variantId });
  const finalState = await readBoundaryState(ctx, session, variantId, 'final', paid.operationId);
  assertPaymentBoundaryStates(initialState, finalState, BigInt(pin.amount));
  const objectiveCandidate = projectM2CatalogObjective({
    publicCatalog,
    components: [paid.deliveryProjection.component],
  });
  assertObjectiveSelectedMinimum(objectiveCandidate, selected);

  const facts = await readCaseDatabaseFacts(ctx, session, `${variantId}-final-database`, variantId);
  const catalogOperations = facts.operations.filter((row) => row.operation_kind === 'catalog');
  const purchaseOperations = facts.operations.filter((row) => row.operation_kind === 'purchase');
  const purchase = purchaseOperations.length === 1 ? purchaseOperations[0]! : null;
  const payment = facts.payments.length === 1 ? facts.payments[0]! : null;
  const delivery = facts.deliveries.length === 1 ? facts.deliveries[0]! : null;
  if (facts.operations.length !== 2 || facts.counts.operations !== '2' || facts.counts.offerOperations !== '0'
    || facts.counts.purchaseOperations !== '1' || catalogOperations.length !== 1
    || String(catalogOperations[0]!.operation_id) !== read.operationId
    || catalogOperations[0]!.status !== 'accepted' || catalogOperations[0]!.receipt_status !== 'not_submitted'
    || purchaseOperations.length !== 1 || String(purchase!.operation_id) !== paid.operationId
    || purchase!.status !== 'delivered' || purchase!.receipt_status !== 'success'
    || purchase!.selected_resource_id !== selected.resourceId || purchase!.selected_offer_id !== selected.offerId
    || String(purchase!.selected_amount_units) !== pin.amount
    || facts.payments.length !== 1 || facts.deliveries.length !== 1 || facts.counts.payments !== '1'
    || facts.counts.deliveries !== '1' || facts.counts.transactionCosts !== '1' || facts.counts.participantCosts !== '0'
    || facts.counts.denials !== '0' || facts.counts.selectedExecutions !== '0'
    || facts.counts.selectedExecutionEvents !== '0'
    || String(payment!.operation_id) !== paid.operationId || String(payment!.amount_units) !== pin.amount
    || String(payment!.token_delta_units) !== pin.amount
    || String(payment!.transaction_hash).toLowerCase() !== paid.transactionHash.toLowerCase()
    || String(payment!.facilitator_address).toLowerCase() !== facilitator
    || String(delivery!.operation_id) !== paid.operationId || delivery!.resource_id !== selected.resourceId
    || String(delivery!.content_sha256).toLowerCase() !== pin.resourceSha256.toLowerCase()
    || Number(delivery!.content_bytes) !== Buffer.from(paid.deliveryProjection.projection.contentBytes, 'base64').byteLength) {
    throw new Error('task_difficulty_v2_m2_durable_effect_counts_or_binding_mismatch');
  }

  const participantActions = [read.participantAction, ...paid.participantActions];
  if (participantActions.length !== 3 || participantActions.map((action) => action.kind).join(',') !== 'inspect_catalog,pay,retrieve') {
    throw new Error('task_difficulty_v2_m2_participant_action_trace_mismatch');
  }
  const catalogRef = ctx.evidence.artifacts.find((artifact) => artifact.path === read.rawResponsePath);
  if (!catalogRef || catalogRef.sha256 !== read.rawResponseSha256) throw new Error('task_difficulty_v2_m2_catalog_evidence_missing');
  const deliveredBytes = Buffer.from(paid.deliveryProjection.projection.contentBytes, 'base64');
  const capture: Record<string, unknown> = {
    schemaVersion: 'bts-m2-difficulty-v2-reference/v1',
    classification: 'local_fork_reference_candidate_not_bts_acceptance',
    status: 'observed_candidate', taskId: 'M2', mode,
    difficultyProfile: { profileId: PROFILE_ID, mode, sourcePath: source.path, sourceSha256: source.sha256,
      manifestSha256: ctx.runtime.manifestSha256 },
    participantToolProtocol: 'separate_payment_delivery_v2',
    participantActionPlan: ['inspect_catalog', 'pay:minimum-qualifying-offer', 'retrieve'],
    countedParticipantActions: participantActions.length,
    participantActions,
    environment: sessionProjection(session),
    initialDatabaseCounts: {
      operations: String(baseline.operations.length), payments: String(baseline.payments.length),
      deliveries: String(baseline.deliveries.length),
    },
    initialState, finalState,
    catalogInspection: {
      operationId: read.operationId, rawResponsePath: read.rawResponsePath,
      rawResponseSha256: read.rawResponseSha256, publicCatalogProjection: publicCatalog,
    },
    objectiveCandidate: {
      ...objectiveCandidate,
      policyReviewStatus: 'candidate_requires_release_review',
    },
    selectedOffer: {
      resourceId: selected.resourceId, offerId: selected.offerId, dataType: selected.dataType,
      amountUsdcUnits: selected.advertisedTotalPriceUsdcUnits, resourceSha256: pin.resourceSha256,
      schema: pin.schema, facilitatorAddress: facilitator,
    },
    payment: {
      operationId: paid.operationId, transactionHash: paid.transactionHash,
      receipt: paid.paymentReceipt, facilitatorGas: paid.facilitatorGas,
    },
    delivery: {
      projection: paid.deliveryProjection.projection,
      component: paid.deliveryProjection.component,
      contentPath: paid.deliveryContentPath,
      contentSha256: paid.deliveryContentSha256,
      contentBytes: deliveredBytes.byteLength,
    },
    durableDatabase: {
      counts: facts.counts, operations: facts.operations, payments: facts.payments,
      deliveries: facts.deliveries, transactionCosts: facts.transactionCosts,
    },
    elapsedObservedMs: Date.now() - startedAt,
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  capture.caseHash = canonicalSha256(capture);
  const candidatePath = 'task-difficulty-v2/candidates/m2-ranked.json';
  await ctx.evidence.writeObservation(candidatePath, 'task-difficulty-v2-m2-ranked-candidate', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId: paid.operationId, variantId, candidate: capture,
  });
  const caseArtifact = ctx.evidence.artifacts.find((artifact) => artifact.path === candidatePath);
  if (!caseArtifact) throw new Error('task_difficulty_v2_m2_candidate_artifact_missing');
  return {
    taskId: 'M2', mode, capture, session, participantActions,
    caseArtifact: { path: caseArtifact.path, sha256: caseArtifact.sha256 },
  };
}
