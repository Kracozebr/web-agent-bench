/**
 * One-task, one-mode local-fork reference captures for the unactivated
 * difficulty-v2 case input profile. Captures are evidence, never scores.
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { RuntimeManifest } from '../manifest.js';
import { apiPath } from './environment.js';
import { sha256Bytes } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { captureBasicDifficultyV2Task, type BasicDifficultyTaskId } from './task-difficulty-v2-basic-capture.js';
import { captureH2ExactPayoutReference } from './task-reference-h1h2-drivers.js';
import { captureM2DifficultyV2Task, validateM2DifficultyV2ProfileTask } from './task-difficulty-v2-m2-capture.js';
import {
  readCaseDatabaseFacts,
  latestBlock,
  readCaseState,
  startFreshCaseGeneration,
} from './task-reference-case-drivers.js';
import {
  inspectSplitCatalog,
  inspectSplitOffer,
  payAndRetrieveSplitResource,
  type SplitParticipantAction,
  type SplitReadOffer,
} from './task-split-resource-capture.js';
import { canonicalSha256 } from './task-reference-cases.js';
import {
  captureH3ReverseSwapV2,
  captureM4ReverseSwapV2,
  resolveH3InputUnits,
  resolveM4InputUnits,
  type ReverseSwapProfileSource,
} from './task-v2-reverse-swap-capture.js';

const PROFILE_PATH = 'infrastructure/owner-identity/task-difficulty-profile-v2.json';
const PROFILE_ID = 'bts-task-difficulty-v2';
const PROFILE_SCHEMA = 'bts-task-case-input-profile/v2';
const PROFILE_CLASSIFICATION = 'candidate_case_inputs_not_capture_or_release';
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type DifficultyTaskId = BasicDifficultyTaskId | 'M1' | 'M2' | 'H1' | 'H2' | 'M4' | 'H3';
export type DifficultyMode = 'ranked' | 'training';

export type DifficultyV2ParticipantAction = SplitParticipantAction | {
  kind: 'transfer';
  operationId: string;
  rawResponsePath: string;
  rawResponseSha256: string;
} | {
  kind: 'wrap' | 'approve' | 'revoke' | 'swap' | 'unwrap';
  operationId: string;
  rawResponsePath: string;
  rawResponseSha256: string;
};

export type DifficultyProfileSource = {
  profile: Record<string, unknown>;
  path: string;
  sha256: string;
  bytes: Uint8Array;
};

export type DifficultyV2TaskCapture = {
  taskId: DifficultyTaskId;
  mode: DifficultyMode;
  capture: Record<string, unknown>;
  session: GenerationSession;
  participantActions: DifficultyV2ParticipantAction[];
  caseArtifact: { path: string; sha256: string };
};

type M1Selection = { resourceId: string; offerId: string; amountUsdcUnits: string };
type H1Component = { resourceId: string; offerId: string; amountUsdcUnits: string };
type H2Obligation = { obligationId: string; recipient: string; amountUsdcUnits: string };

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_difficulty_v2_${label}_invalid`);
  return value;
}

function reverseSwapActionKind(value: unknown): 'inspect_offer' | 'pay' | 'retrieve' | 'wrap' | 'approve' | 'swap' {
  switch (value) {
    case 'inspect_offer':
    case 'pay':
    case 'retrieve':
    case 'wrap':
    case 'approve':
    case 'swap':
      return value;
    default:
      throw new Error('task_difficulty_v2_reverse_swap_participant_action_kind_invalid');
  }
}

function profileTask(source: DifficultyProfileSource, taskId: DifficultyTaskId): Record<string, unknown> {
  const tasks = record(source.profile.tasks);
  const task = record(tasks?.[taskId]);
  if (!task) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_profile_task_missing`);
  return task;
}

function profileMode(task: Record<string, unknown>, mode: DifficultyMode): Record<string, unknown> {
  const modes = record(task.modes);
  const selected = record(modes?.[mode]);
  if (!selected) throw new Error('task_difficulty_v2_profile_mode_missing');
  return selected;
}

function manifestOffer(manifest: RuntimeManifest, resourceId: string, offerId: string): { amount: string; resourceSha256: string } {
  const resources = manifest.x402.catalog?.filter((resource) => resource.resourceId === resourceId) ?? [];
  const resource = resources.length === 1 ? resources[0] : undefined;
  const offers = resource?.offers.filter((offer) => offer.id === offerId) ?? [];
  const offer = offers.length === 1 ? offers[0] : undefined;
  if (!resource || !offer) throw new Error('task_difficulty_v2_profile_resource_or_offer_not_pinned');
  return { amount: offer.amount, resourceSha256: resource.resourceSha256 };
}

function validateM1Profile(ctx: ProbeContext, source: DifficultyProfileSource, mode: DifficultyMode): M1Selection {
  const task = profileTask(source, 'M1');
  const selected = profileMode(task, mode);
  const plan = Array.isArray(task.participantActionPlan) ? task.participantActionPlan : [];
  if (task.countedParticipantActions !== 3
    || JSON.stringify(plan) !== JSON.stringify(['inspect_offer', 'pay', 'retrieve'])) {
    throw new Error('task_difficulty_v2_m1_profile_action_plan_invalid');
  }
  const resourceId = requiredString(selected.resourceId, 'm1_resource_id');
  const offerId = requiredString(selected.offerId, 'm1_offer_id');
  const amountUsdcUnits = requiredString(selected.amountUsdcUnits, 'm1_amount');
  const pin = manifestOffer(ctx.runtime.manifest, resourceId, offerId);
  if (!UINT.test(amountUsdcUnits) || BigInt(amountUsdcUnits) <= 0n || amountUsdcUnits !== pin.amount) {
    throw new Error('task_difficulty_v2_m1_profile_terms_not_pinned');
  }
  return { resourceId, offerId, amountUsdcUnits };
}

function validateH1Profile(ctx: ProbeContext, source: DifficultyProfileSource, mode: DifficultyMode): H1Component[] {
  const task = profileTask(source, 'H1');
  const selected = profileMode(task, mode);
  const requiredResources = Array.isArray(task.requiredResources) ? task.requiredResources : [];
  const expectedResources = ['bef-resource-v1', 'bef-market-state-brief-v1', 'bef-treasury-risk-policy-v2'];
  const plan = Array.isArray(task.participantActionPlan) ? task.participantActionPlan : [];
  const expectedPlan = ['inspect_catalog', 'pay:component-1', 'retrieve:component-1', 'pay:component-2',
    'retrieve:component-2', 'pay:component-3', 'retrieve:component-3'];
  const rawComponents = Array.isArray(selected.components) ? selected.components : [];
  if (task.requiredDistinctPaidComponents !== 3 || task.countedParticipantActions !== 7
    || JSON.stringify(plan) !== JSON.stringify(expectedPlan)
    || new Set(requiredResources).size !== 3
    || expectedResources.some((resourceId) => !requiredResources.includes(resourceId))
    || rawComponents.length !== 3) {
    throw new Error('task_difficulty_v2_h1_profile_action_or_component_plan_invalid');
  }
  const components: H1Component[] = rawComponents.map((value) => {
    const item = record(value);
    const resourceId = requiredString(item?.resourceId, 'h1_resource_id');
    const offerId = requiredString(item?.offerId, 'h1_offer_id');
    const amountUsdcUnits = requiredString(item?.amountUsdcUnits, 'h1_amount');
    const pin = manifestOffer(ctx.runtime.manifest, resourceId, offerId);
    if (!UINT.test(amountUsdcUnits) || BigInt(amountUsdcUnits) <= 0n || amountUsdcUnits !== pin.amount) {
      throw new Error('task_difficulty_v2_h1_profile_terms_not_pinned');
    }
    return { resourceId, offerId, amountUsdcUnits };
  });
  if (new Set(components.map((item) => item.resourceId)).size !== 3
    || expectedResources.some((resourceId) => !components.some((item) => item.resourceId === resourceId))) {
    throw new Error('task_difficulty_v2_h1_profile_resources_not_distinct');
  }
  return components;
}

function validateH2Profile(source: DifficultyProfileSource, mode: DifficultyMode): H2Obligation[] {
  const task = profileTask(source, 'H2');
  const selected = profileMode(task, mode);
  const rawObligations = Array.isArray(selected.obligations) ? selected.obligations : [];
  const plan = Array.isArray(task.participantActionPlan) ? task.participantActionPlan : [];
  const expectedPlan = Array.from({ length: 6 }, (_unused, index) => `transfer:obligation-${index + 1}`);
  if (task.requiredDistinctObligations !== 6 || task.countedParticipantActions !== 6
    || task.assetId !== 'USDC' || JSON.stringify(plan) !== JSON.stringify(expectedPlan) || rawObligations.length !== 6) {
    throw new Error('task_difficulty_v2_h2_profile_action_or_obligation_plan_invalid');
  }
  const obligations: H2Obligation[] = rawObligations.map((value) => {
    const item = record(value);
    const obligationId = requiredString(item?.obligationId, 'h2_obligation_id');
    const recipient = requiredString(item?.recipient, 'h2_recipient').toLowerCase();
    const amountUsdcUnits = requiredString(item?.amountUsdcUnits, 'h2_amount');
    if (!ADDRESS.test(recipient) || !UINT.test(amountUsdcUnits) || BigInt(amountUsdcUnits) <= 0n) {
      throw new Error('task_difficulty_v2_h2_profile_obligation_invalid');
    }
    return { obligationId, recipient, amountUsdcUnits };
  });
  if (new Set(obligations.map((item) => item.obligationId)).size !== 6
    || new Set(obligations.map((item) => item.recipient)).size !== 6) {
    throw new Error('task_difficulty_v2_h2_profile_obligations_not_distinct');
  }
  return obligations;
}

/** Load and bind the unactivated source profile to the current runtime manifest. */
export async function loadDifficultyProfileV2(ctx: Pick<ProbeContext, 'runtime'>): Promise<DifficultyProfileSource> {
  const path = resolve(ctx.runtime.root, PROFILE_PATH);
  const bytes = await readFile(path);
  const profileSha256 = sha256(bytes);
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString()) as unknown; }
  catch { throw new Error('task_difficulty_v2_profile_json_invalid'); }
  const profile = record(parsed);
  const compatibility = record(profile?.compatibility);
  const manifestPin = record(profile?.runtimeManifest);
  const measurementBoundary = record(profile?.measurementBoundary);
  if (!profile || profile.schemaVersion !== PROFILE_SCHEMA || profile.profileId !== PROFILE_ID
    || profile.classification !== PROFILE_CLASSIFICATION || profile.status !== 'source_profile_candidate_unactivated'
    || compatibility?.defaultProfile !== 'legacy' || compatibility.legacyCapturesAreImmutable !== true
    || compatibility.v2RequiresExplicitSelection !== true
    || manifestPin?.path !== 'infrastructure/benchmark-environment/manifest.json'
    || typeof manifestPin.sha256 !== 'string' || manifestPin.sha256.toLowerCase() !== ctx.runtime.manifestSha256.toLowerCase()
    || measurementBoundary?.approvalStatus !== 'not claimed'
    || measurementBoundary.releaseReadiness !== 'blocked_until_fresh_capture_and_release_review') {
    throw new Error('task_difficulty_v2_profile_manifest_or_classification_mismatch');
  }
  return { profile, path: PROFILE_PATH, sha256: profileSha256, bytes };
}

export function validateDifficultyV2ProfileTask(
  ctx: ProbeContext,
  source: DifficultyProfileSource,
  taskId: DifficultyTaskId,
  mode: DifficultyMode,
): M1Selection | H1Component[] | H2Obligation[] | string | null {
  if (taskId === 'M1') return validateM1Profile(ctx, source, mode);
  if (taskId === 'M2') {
    validateM2DifficultyV2ProfileTask(source, mode);
    return null;
  }
  if (taskId === 'H1') return validateH1Profile(ctx, source, mode);
  if (taskId === 'H2') return validateH2Profile(source, mode);
  if (taskId === 'M4') return resolveM4InputUnits(source.profile, mode);
  if (mode !== 'ranked') throw new Error('task_difficulty_v2_h3_ranked_only');
  return resolveH3InputUnits(source.profile);
}

function exactTermsFromRead(readOffers: readonly SplitReadOffer[], resourceId: string, offerId: string, amount: string): SplitReadOffer {
  const matches = readOffers.filter((item) => item.resourceId === resourceId && item.offerId === offerId);
  if (matches.length !== 1 || matches[0]!.acceptedTerms.amount !== amount) {
    throw new Error('task_difficulty_v2_observed_public_offer_does_not_match_profile');
  }
  return matches[0]!;
}

function actualFacilitatorAddress(ctx: ProbeContext): string {
  const services = record(ctx.capability.services);
  const facilitator = record(services?.facilitator);
  const address = requiredString(facilitator?.address, 'facilitator_address').toLowerCase();
  if (!ADDRESS.test(address)) throw new Error('task_difficulty_v2_facilitator_address_invalid');
  return address;
}

async function readBoundaryState(
  ctx: ProbeContext,
  session: GenerationSession,
  variantId: string,
  suffix: 'initial' | 'final',
  operationId: string | null,
): Promise<Record<string, unknown>> {
  const block = await latestBlock(ctx, operationId, variantId, `task-difficulty-v2-${variantId}-${suffix}-state`);
  const state = await readCaseState(ctx, {
    session, blockTag: block.tag, blockHash: block.hash, operationId, variantId,
    label: `task-difficulty-v2-${variantId}-${suffix}-state`,
  });
  if (String(state.blockNumber) !== block.number || String(state.blockHash).toLowerCase() !== block.hash.toLowerCase()
    || String(state.payerAddress).toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error(`task_difficulty_v2_${suffix}_state_cutoff_mismatch`);
  }
  return state;
}

function assertPaymentBoundaryStates(initial: Record<string, unknown>, final: Record<string, unknown>, amount: bigint, label: string): void {
  const value = (state: Record<string, unknown>, field: string): bigint => {
    const parsed = String(state[field] ?? '');
    if (!UINT.test(parsed)) throw new Error(`task_difficulty_v2_${label}_state_${field}_invalid`);
    return BigInt(parsed);
  };
  if (value(initial, 'payerUsdcUnits') - value(final, 'payerUsdcUnits') !== amount
    || value(initial, 'payerNativeEthWei') !== value(final, 'payerNativeEthWei')
    || value(initial, 'payerWethUnits') !== value(final, 'payerWethUnits')
    || value(initial, 'usdcRouterAllowanceUnits') !== value(final, 'usdcRouterAllowanceUnits')
    || value(initial, 'wethRouterAllowanceUnits') !== value(final, 'wethRouterAllowanceUnits')) {
    throw new Error(`task_difficulty_v2_${label}_common_block_effect_mismatch`);
  }
}

function sessionProjection(session: GenerationSession): Record<string, string> {
  return {
    envId: session.envId,
    generationId: session.generationId,
    participantId: session.participantId,
    payerAddress: session.payerAddress.toLowerCase(),
  };
}

function assertBaseline(snapshot: Awaited<ReturnType<ProbeContext['database']['snapshot']>>, session: GenerationSession, label: string): void {
  if (snapshot.generation.length !== 1 || String(snapshot.generation[0]!.generation_id).toLowerCase() !== session.generationId.toLowerCase()
    || String(snapshot.generation[0]!.participant_id) !== session.participantId || snapshot.generation[0]!.status !== 'active'
    || snapshot.operations.length !== 0 || snapshot.payments.length !== 0 || snapshot.deliveries.length !== 0
    || snapshot.denials.length !== 0) {
    throw new Error(`task_difficulty_v2_${label}_generation_baseline_not_clean`);
  }
}

function caseArtifact(ctx: ProbeContext, path: string): { path: string; sha256: string } {
  const artifact = ctx.evidence.artifacts.find((item) => item.path === path);
  if (!artifact) throw new Error('task_difficulty_v2_case_artifact_missing');
  return { path: artifact.path, sha256: artifact.sha256 };
}

async function writeCandidate(ctx: ProbeContext, path: string, candidate: Record<string, unknown>, operationId: string | null, variantId: string): Promise<{ path: string; sha256: string }> {
  await ctx.evidence.writeObservation(path, path.replaceAll('/', '-'), {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId, variantId, candidate,
  });
  return caseArtifact(ctx, path);
}

async function captureM1(ctx: ProbeContext, mode: DifficultyMode, source: DifficultyProfileSource): Promise<DifficultyV2TaskCapture> {
  const selection = validateM1Profile(ctx, source, mode);
  const variantId = `bts_m1_${mode}_difficulty_v2_split_reference`;
  const session = await startFreshCaseGeneration(ctx, { caseId: 'm1', scenarioId: 'BEF-SC-005', variantId });
  const baseline = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    variantId, label: `${variantId}-baseline` });
  assertBaseline(baseline, session, 'm1');
  const initialState = await readBoundaryState(ctx, session, variantId, 'initial', null);
  const facilitator = actualFacilitatorAddress(ctx);
  const startedAt = Date.now();
  const read = await inspectSplitOffer(ctx, session, selection.resourceId, { variantId, label: variantId });
  const advertised = exactTermsFromRead(read.offers, selection.resourceId, selection.offerId, selection.amountUsdcUnits);
  if (advertised.acceptedTerms.payTo.toLowerCase() !== facilitator) throw new Error('task_difficulty_v2_m1_facilitator_read_mismatch');
  const paid = await payAndRetrieveSplitResource(ctx, session, selection, read, { variantId, label: variantId });
  const finalState = await readBoundaryState(ctx, session, variantId, 'final', paid.operationId);
  assertPaymentBoundaryStates(initialState, finalState, BigInt(selection.amountUsdcUnits), 'm1');
  const facts = await readCaseDatabaseFacts(ctx, session, `${variantId}-final-database`, variantId);
  if (facts.operations.length !== 2 || facts.counts.offerOperations !== '1' || facts.counts.purchaseOperations !== '1'
    || facts.payments.length !== 1 || facts.deliveries.length !== 1 || facts.counts.payments !== '1'
    || facts.counts.deliveries !== '1' || facts.counts.transactionCosts !== '1' || facts.counts.participantCosts !== '0') {
    throw new Error('task_difficulty_v2_m1_durable_effect_counts_mismatch');
  }
  const participantActions = [read.participantAction, ...paid.participantActions];
  if (participantActions.length !== 3 || participantActions.map((item) => item.kind).join(',') !== 'inspect_offer,pay,retrieve') {
    throw new Error('task_difficulty_v2_m1_participant_action_trace_mismatch');
  }
  const capture: Record<string, unknown> = {
    schemaVersion: 'bts-m1-difficulty-v2-reference/v1',
    classification: 'local_fork_reference_candidate_not_bts_acceptance',
    status: 'observed_candidate', taskId: 'M1', mode,
    difficultyProfile: { profileId: PROFILE_ID, mode, sourcePath: source.path, sourceSha256: source.sha256,
      manifestSha256: ctx.runtime.manifestSha256 },
    participantToolProtocol: 'separate_payment_delivery_v2',
    participantActionPlan: ['inspect_offer', 'pay', 'retrieve'],
    countedParticipantActions: participantActions.length, participantActions,
    environment: sessionProjection(session),
    reference: {
      resourceId: selection.resourceId, offerId: selection.offerId, amountUsdcUnits: selection.amountUsdcUnits,
      facilitatorAddress: facilitator,
      inspection: { operationId: read.operationId, rawResponsePath: read.rawResponsePath, rawResponseSha256: read.rawResponseSha256 },
      payment: { operationId: paid.operationId, transactionHash: paid.transactionHash, receipt: paid.paymentReceipt,
        facilitatorGas: paid.facilitatorGas },
      delivery: { projection: paid.deliveryProjection.projection, schema: manifestSchema(ctx.runtime.manifest, selection.resourceId),
        contentPath: paid.deliveryContentPath, contentSha256: paid.deliveryContentSha256,
        contentBytes: Buffer.from(paid.deliveryProjection.projection.contentBytes, 'base64').byteLength },
    },
    durableDatabase: {
      counts: facts.counts, operations: facts.operations, payments: facts.payments,
      deliveries: facts.deliveries, transactionCosts: facts.transactionCosts,
    },
    initialState,
    finalState,
    initialDatabaseCounts: { operations: '0', payments: '0', deliveries: '0' },
    elapsedObservedMs: Date.now() - startedAt,
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  const path = `task-difficulty-v2/candidates/m1-${mode}.json`;
  const artifact = await writeCandidate(ctx, path, capture, paid.operationId, variantId);
  return { taskId: 'M1', mode, capture, session, participantActions, caseArtifact: artifact };
}

function manifestSchema(manifest: RuntimeManifest, resourceId: string): string {
  const matches = manifest.x402.catalog?.filter((resource) => resource.resourceId === resourceId) ?? [];
  if (matches.length !== 1) throw new Error('task_difficulty_v2_resource_schema_missing');
  return matches[0]!.schema;
}

async function captureH1(ctx: ProbeContext, mode: DifficultyMode, source: DifficultyProfileSource): Promise<DifficultyV2TaskCapture> {
  const components = validateH1Profile(ctx, source, mode);
  const variantId = `bts_h1_${mode}_difficulty_v2_split_reference`;
  const session = await startFreshCaseGeneration(ctx, { caseId: 'h1', scenarioId: 'BEF-SC-009', variantId });
  const baseline = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    variantId, label: `${variantId}-baseline` });
  assertBaseline(baseline, session, 'h1');
  const initialState = await readBoundaryState(ctx, session, variantId, 'initial', null);
  const facilitator = actualFacilitatorAddress(ctx);
  const startedAt = Date.now();
  const read = await inspectSplitCatalog(ctx, session, { variantId, label: variantId });
  const participantActions: SplitParticipantAction[] = [read.participantAction];
  const purchases: Array<Record<string, unknown>> = [];
  const deliveryProjections: Array<Record<string, unknown>> = [];
  let finalOperationId: string | null = null;
  for (const [index, component] of components.entries()) {
    const advertised = exactTermsFromRead(read.offers, component.resourceId, component.offerId, component.amountUsdcUnits);
    if (advertised.acceptedTerms.payTo.toLowerCase() !== facilitator) {
      throw new Error('task_difficulty_v2_h1_facilitator_read_mismatch');
    }
    const paid = await payAndRetrieveSplitResource(ctx, session, component, read, { variantId, label: `${variantId}-component-${index + 1}` });
    finalOperationId = paid.operationId;
    participantActions.push(...paid.participantActions);
    const contentBytes = Buffer.from(paid.deliveryProjection.projection.contentBytes, 'base64');
    const projectionPath = `task-difficulty-v2/h1/delivery-projections/${paid.operationId}.json`;
    await ctx.evidence.writeObservation(projectionPath, `h1-delivery-projection-${paid.operationId}`, {
      schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
      operationId: paid.operationId, variantId,
      projection: paid.deliveryProjection.projection,
      component: paid.deliveryProjection.component,
      contentBytesSha256: paid.deliveryProjection.contentBytesSha256,
      parsedContent: paid.deliveryProjection.parsedContent,
    });
    const projectionRef = caseArtifact(ctx, projectionPath);
    purchases.push({
      operationId: paid.operationId,
      resourceId: component.resourceId,
      resourceSha256: manifestOffer(ctx.runtime.manifest, component.resourceId, component.offerId).resourceSha256,
      offerId: component.offerId,
      amountUnits: component.amountUsdcUnits,
      paymentTransactionHash: paid.transactionHash,
      receiptStatus: '0x1',
      selectedResourcePersisted: true,
      selectedOfferPersisted: true,
      paymentAndDeliveryPersisted: true,
      deliveredContentBytes: contentBytes.byteLength,
      deliveredContentPath: paid.deliveryContentPath,
      deliveredContentSha256: paid.deliveryContentSha256,
      deliveryProjectionPath: projectionRef.path,
      deliveryProjectionSha256: projectionRef.sha256,
      facilitatorGas: paid.facilitatorGas,
      paymentReceipt: paid.paymentReceipt,
    });
    deliveryProjections.push({
      operationId: paid.operationId,
      projectionPath: projectionRef.path,
      projectionSha256: projectionRef.sha256,
      rawContentPath: paid.deliveryContentPath,
      rawContentSha256: paid.deliveryContentSha256,
      projection: paid.deliveryProjection.projection,
      component: paid.deliveryProjection.component,
      contentHash: paid.deliveryProjection.contentBytesSha256,
    });
  }
  const finalState = await readBoundaryState(ctx, session, variantId, 'final', finalOperationId);
  const totalUsdcUnits = components.reduce((total, component) => total + BigInt(component.amountUsdcUnits), 0n);
  assertPaymentBoundaryStates(initialState, finalState, totalUsdcUnits, 'h1');
  if (participantActions.length !== 7 || participantActions.map((item) => item.kind).join(',')
    !== 'inspect_catalog,pay,retrieve,pay,retrieve,pay,retrieve') {
    throw new Error('task_difficulty_v2_h1_participant_action_trace_mismatch');
  }
  const facts = await readCaseDatabaseFacts(ctx, session, `${variantId}-final-database`, variantId);
  const catalogOperations = facts.operations.filter((row) => row.operation_kind === 'catalog');
  if (facts.operations.length !== 4 || facts.counts.operations !== '4' || facts.counts.offerOperations !== '0'
    || catalogOperations.length !== 1 || String(catalogOperations[0]!.operation_id) !== read.operationId
    || catalogOperations[0]!.status !== 'accepted' || catalogOperations[0]!.receipt_status !== 'not_submitted'
    || facts.counts.purchaseOperations !== '3'
    || facts.payments.length !== 3 || facts.deliveries.length !== 3 || facts.counts.payments !== '3'
    || facts.counts.deliveries !== '3' || facts.counts.transactionCosts !== '3' || facts.counts.participantCosts !== '0') {
    throw new Error('task_difficulty_v2_h1_durable_effect_counts_mismatch');
  }
  const captureBody = {
    participantToolProtocol: 'separate_payment_delivery_v2',
    participantActionPlan: ['inspect_catalog', 'pay:component-1', 'retrieve:component-1', 'pay:component-2',
      'retrieve:component-2', 'pay:component-3', 'retrieve:component-3'],
    countedParticipantActions: participantActions.length,
    participantActions,
    environment: sessionProjection(session),
    facilitatorAddress: facilitator,
    initialState,
    finalState,
    initialDatabaseCounts: {
      operations: String(baseline.operations.length),
      payments: String(baseline.payments.length),
      deliveries: String(baseline.deliveries.length),
    },
    catalogInspection: { operationId: read.operationId, rawResponsePath: read.rawResponsePath,
      rawResponseSha256: read.rawResponseSha256 },
    purchases,
    deliveryProjections,
    durableDatabase: {
      counts: facts.counts, operations: facts.operations, payments: facts.payments,
      deliveries: facts.deliveries, transactionCosts: facts.transactionCosts,
    },
  };
  const componentsWithArtifactRefs = components.map((component, index) => ({
    componentId: component.resourceId,
    resourceId: component.resourceId,
    offerId: component.offerId,
    amountUsdcUnits: component.amountUsdcUnits,
    resourceSha256: purchases[index]!.resourceSha256,
    schema: manifestSchema(ctx.runtime.manifest, component.resourceId),
    deliveryProjection: deliveryProjections[index]!.projection,
    dataComponent: deliveryProjections[index]!.component,
    permittedSources: (deliveryProjections[index]!.component as { sourceIds: string[] }).sourceIds,
    deliveryOperationId: purchases[index]!.operationId,
    paymentTransactionHash: purchases[index]!.paymentTransactionHash,
    deliveredContentArtifact: purchases[index]!.deliveredContentPath,
    deliveredContentSha256: purchases[index]!.deliveredContentSha256,
    deliveryProjectionArtifact: purchases[index]!.deliveryProjectionPath,
    deliveryProjectionSha256: purchases[index]!.deliveryProjectionSha256,
  }));
  const candidate: Record<string, unknown> = {
    schemaVersion: 'bts-h1-observed-case-inputs/v2',
    classification: 'local_reference_profile_candidate_not_release_manifest',
    taskId: 'H1', mode, status: 'observed_candidate',
    difficultyProfile: { profileId: PROFILE_ID, mode, sourcePath: source.path, sourceSha256: source.sha256,
      manifestSha256: ctx.runtime.manifestSha256 },
    participantToolProtocol: 'separate_payment_delivery_v2',
    countedParticipantActions: participantActions.length,
    participantActions,
    environment: sessionProjection(session),
    facilitatorAddress: facilitator,
    initialState,
    finalState,
    initialDatabaseCounts: {
      operations: String(baseline.operations.length),
      payments: String(baseline.payments.length),
      deliveries: String(baseline.deliveries.length),
    },
    requiredComponentCount: 3,
    components: componentsWithArtifactRefs,
    servicePaymentAsset: { symbol: 'USDC', assetId: ctx.runtime.manifest.x402.asset.toLowerCase(),
      provenance: 'synthetic_fixture_balance_on_isolated_local_fork' },
    servicePaymentNetwork: ctx.runtime.manifest.x402.network,
    durableDatabase: captureBody.durableDatabase,
    rawCapture: captureBody,
    elapsedObservedMs: Date.now() - startedAt,
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  candidate.caseHash = canonicalSha256(candidate);
  const path = `task-difficulty-v2/candidates/h1-${mode}.json`;
  const artifact = await writeCandidate(ctx, path, candidate, purchases.at(-1)?.operationId as string ?? null, variantId);
  return { taskId: 'H1', mode, capture: candidate, session, participantActions, caseArtifact: artifact };
}

type H2Action = Extract<DifficultyV2ParticipantAction, { kind: 'transfer' }>;

async function captureH2(ctx: ProbeContext, mode: DifficultyMode, source: DifficultyProfileSource): Promise<DifficultyV2TaskCapture> {
  const obligations = validateH2Profile(source, mode);
  const variantId = `bts_h2_${mode}_difficulty_v2_payout_reference`;
  const actions: H2Action[] = [];
  const secretStrings = () => ctx.secretValues.filter((secret) => secret.length > 0);
  const original = ctx.transport.request;
  let requestIndex = 0;
  ctx.transport.request = async (input) => {
    const response = await original.call(ctx.transport, input);
    let route: string | null = null;
    try { route = new URL(input.url).pathname; } catch { /* The original transport records the route outcome. */ }
    if (input.boundary !== 'actual-tool-http' || input.method.toUpperCase() !== 'POST'
      || route !== `/tools/${ctx.env.envId}/transfer`) return response;

    requestIndex += 1;
    const body = record(response.body);
    const selected = record(body?.selectedAction);
    const operationId = response.operationId ?? (typeof body?.operationId === 'string' ? body.operationId : null);
    if (!operationId || !UUID.test(operationId)) throw new Error('task_difficulty_v2_h2_transfer_operation_missing');
    const raw = response.rawBody;
    if (secretStrings().some((secret) => raw.includes(Buffer.from(secret)))) {
      throw new Error('task_difficulty_v2_h2_transfer_raw_response_contains_secret');
    }
    const rawResponsePath = `task-difficulty-v2/h2/responses/${operationId}-transfer.json`;
    await ctx.evidence.writeRawJson(rawResponsePath, raw, 'actual-tool-http');
    const expected = obligations[requestIndex - 1];
    if (!expected || response.status < 200 || response.status >= 300 || body?.outcome !== 'success'
      || selected?.kind !== 'transfer' || String(selected.amountUnits) !== expected.amountUsdcUnits
      || String(selected.recipient).toLowerCase() !== expected.recipient
      || String(selected.token).toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase()) {
      throw new Error('task_difficulty_v2_h2_transfer_response_binding_mismatch');
    }
    actions.push({ kind: 'transfer', operationId, rawResponsePath, rawResponseSha256: sha256Bytes(raw) });
    return response;
  };

  let candidate: Record<string, unknown>;
  try {
    candidate = await captureH2ExactPayoutReference(ctx, {
      difficultyProfile: { profileId: PROFILE_ID, mode },
    });
  } finally {
    ctx.transport.request = original;
  }
  const session = ctx.primarySession;
  if (!session || actions.length !== 6 || requestIndex !== 6) throw new Error('task_difficulty_v2_h2_participant_action_trace_incomplete');
  const candidateObligations = Array.isArray(candidate.obligations) ? candidate.obligations.map(record) : [];
  const receiptIds = candidateObligations.map((item) => String(record(item?.receipt)?.operationId ?? ''));
  if (candidateObligations.length !== obligations.length || receiptIds.some((operationId, index) =>
    operationId !== actions[index]?.operationId || candidateObligations[index]?.recipient !== obligations[index]?.recipient
      || String(candidateObligations[index]?.amountUnits) !== obligations[index]?.amountUsdcUnits)
    || new Set(actions.map((item) => item.operationId)).size !== 6) {
    throw new Error('task_difficulty_v2_h2_transfer_receipts_do_not_match_obligations');
  }
  const participantActions = [...actions];
  const { caseHash: _legacyCaseHash, ...candidateWithoutLegacyHash } = candidate;
  const capture: Record<string, unknown> = {
    ...candidateWithoutLegacyHash,
    participantToolProtocol: 'separate_payment_delivery_v2',
    participantActionPlan: obligations.map((_item, index) => `transfer:obligation-${index + 1}`),
    countedParticipantActions: participantActions.length,
    participantActions,
    difficultyProfileEvidence: { path: source.path, sha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  capture.caseHash = canonicalSha256(capture);
  const candidatePath = `task-difficulty-v2/candidates/h2-${mode}.json`;
  const artifact = await writeCandidate(ctx, candidatePath, capture, actions.at(-1)?.operationId ?? null, variantId);
  return { taskId: 'H2', mode, capture, session, participantActions, caseArtifact: artifact };
}

/** Capture exactly one approved task/mode in one fresh, scoped generation. */
export async function captureDifficultyV2Task(ctx: ProbeContext, input: {
  taskId: DifficultyTaskId; mode: DifficultyMode; source: DifficultyProfileSource;
  recipient?: string;
}): Promise<DifficultyV2TaskCapture> {
  if (input.recipient !== undefined && input.taskId !== 'S1') throw new Error('task_transfer_recipient_scope_invalid');
  if (ctx.runtime.manifest.tools.participantProtocol !== 'separate_payment_delivery_v2') {
    throw new Error('task_difficulty_v2_participant_protocol_not_pinned');
  }
  if (input.taskId === 'S1' || input.taskId === 'S2' || input.taskId === 'S3'
    || input.taskId === 'S4' || input.taskId === 'M3') {
    return captureBasicDifficultyV2Task(ctx, { taskId: input.taskId, mode: input.mode, source: input.source,
      ...(input.recipient === undefined ? {} : { recipient: input.recipient }) });
  }
  if (input.taskId === 'M2') return captureM2DifficultyV2Task(ctx, input.mode, input.source);
  validateDifficultyV2ProfileTask(ctx, input.source, input.taskId, input.mode);
  if (input.taskId === 'M1') return captureM1(ctx, input.mode, input.source);
  if (input.taskId === 'H1') return captureH1(ctx, input.mode, input.source);
  if (input.taskId === 'H2') return captureH2(ctx, input.mode, input.source);
  const profileSource: ReverseSwapProfileSource = {
    profile: input.source.profile, path: input.source.path, sha256: input.source.sha256,
  };
  if (input.taskId === 'M4') {
    const captureValue = await captureM4ReverseSwapV2(ctx, { mode: input.mode, profileSource });
    return adaptReverseSwapCapture(ctx, 'M4', input.mode, captureValue);
  }
  const captureValue = await captureH3ReverseSwapV2(ctx, profileSource);
  return adaptReverseSwapCapture(ctx, 'H3', input.mode, captureValue);
}

function adaptReverseSwapCapture(ctx: ProbeContext, taskId: 'M4' | 'H3', mode: DifficultyMode, value: Record<string, unknown>): DifficultyV2TaskCapture {
  const session = ctx.primarySession;
  const rawActions = Array.isArray(value.participantActions) ? value.participantActions.map(record) : [];
  const artifact = record(value.artifact);
  if (!session || rawActions.length !== (taskId === 'M4' ? 3 : 6)
    || !artifact || typeof artifact.path !== 'string' || typeof artifact.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(artifact.sha256)) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_capture_shape_invalid`);
  }
  const participantActions = rawActions.map((item) => {
    const kind = reverseSwapActionKind(item?.kind);
    const operationId = requiredString(item?.operationId, `${taskId.toLowerCase()}_action_operation_id`);
    const rawResponsePath = requiredString(item?.rawResponsePath, `${taskId.toLowerCase()}_action_response_path`);
    const rawResponseSha256 = requiredString(item?.rawResponseSha256, `${taskId.toLowerCase()}_action_response_hash`);
    if (!/^[0-9a-f]{64}$/i.test(rawResponseSha256)) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_action_response_hash_invalid`);
    return { kind, operationId, rawResponsePath, rawResponseSha256 };
  });
  const expectedKinds = taskId === 'M4'
    ? ['wrap', 'approve', 'swap']
    : ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'];
  if (participantActions.some((action, index) => action.kind !== expectedKinds[index])) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_participant_action_order_invalid`);
  }
  return {
    taskId, mode, capture: value, session, participantActions,
    caseArtifact: { path: artifact.path, sha256: artifact.sha256 },
  };
}

/** Fence exactly the capture generation and confirm it independently via the observer. */
export async function fenceDifficultyV2Generation(ctx: ProbeContext, session: GenerationSession, variantId: string): Promise<Record<string, unknown>> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `${variantId}-generation-fence`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/generations/${session.generationId}/fence`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  const body = record(response.body);
  if (response.status !== 200 || body?.status !== 'fenced' || body.signerErased !== true
    || (body.generationId !== undefined && String(body.generationId).toLowerCase() !== session.generationId.toLowerCase())) {
    throw new Error(`task_difficulty_v2_generation_fence_failed_${response.status}`);
  }
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId,
    label: `${variantId}-generation-fence-independent-snapshot`,
  });
  const generation = snapshot.generation.length === 1 ? snapshot.generation[0]! : null;
  const unresolved = snapshot.operations.filter((row) => ['awaiting_payment', 'verifying', 'settling', 'settlement_unknown']
    .includes(String(row.status)) || String(row.receipt_status) === 'unknown');
  if (!generation || String(generation.generation_id).toLowerCase() !== session.generationId.toLowerCase()
    || String(generation.participant_id) !== session.participantId
    || String(generation.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || generation.status !== 'fenced') {
    throw new Error('task_difficulty_v2_generation_fence_not_independently_confirmed');
  }
  return {
    status: 'fenced', signerErased: true,
    envId: session.envId, generationId: session.generationId,
    independentObserver: {
      status: generation.status, participantId: generation.participant_id,
      payerAddress: String(generation.payer_address).toLowerCase(),
      economicOutcome: unresolved.length ? 'unresolved' : 'settled_or_absent',
      unresolvedOperationCount: unresolved.length,
      unresolvedOperations: unresolved.map((row) => ({
        operationId: String(row.operation_id ?? ''),
        status: String(row.status ?? 'unknown'),
        receiptStatus: row.receipt_status === null || row.receipt_status === undefined ? null : String(row.receipt_status),
      })),
    },
  };
}
