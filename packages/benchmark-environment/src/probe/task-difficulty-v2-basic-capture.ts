/**
 * Difficulty-v2 references for the unchanged simple and medium task paths.
 * Inputs are carried forward from the approved reference/training captures;
 * this module records evidence and never creates an acceptance score.
 */
import type { RuntimeManifest } from '../manifest.js';
import { sha256Bytes, sanitizeValue } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { captureSelectedUsdcTransfer } from './task-transfer-capture.js';
import { captureS2ReadonlyOffer, latestBlock, readCaseDatabaseFacts, readCaseState, startFreshCaseGeneration } from './task-reference-case-drivers.js';
import { captureS4M3M4 } from './task-native-capture.js';
import { inspectSplitCatalog, type SplitParticipantAction } from './task-split-resource-capture.js';
import type { PublicCatalogProjection } from './task-reference-catalog-objectives.js';
import { canonicalSha256 } from './task-reference-cases.js';

export type BasicDifficultyTaskId = 'S1' | 'S2' | 'S3' | 'S4' | 'M3';
export type BasicDifficultyMode = 'ranked' | 'training';
export type BasicDifficultyActionKind = 'transfer' | 'inspect_offer' | 'inspect_catalog' | 'revoke' | 'approve' | 'swap' | 'unwrap';
export type BasicDifficultyAction = {
  kind: BasicDifficultyActionKind;
  operationId: string;
  rawResponsePath: string;
  rawResponseSha256: string;
};
export type BasicDifficultyCapture = {
  taskId: BasicDifficultyTaskId;
  mode: BasicDifficultyMode;
  capture: Record<string, unknown>;
  session: GenerationSession;
  participantActions: BasicDifficultyAction[];
  caseArtifact: { path: string; sha256: string };
};

export type BasicDifficultyPolicy = {
  source: 'existing_ranked_reference_default' | 'existing_open_training_reference';
  amountUnits?: string;
  resourceId?: string;
  offerId?: string;
  initialAllowanceUnits?: string;
  publicExactQuote?: boolean;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_difficulty_v2_${label}_invalid`);
  return value;
}

/** The existing approved task inputs; these do not alter the v2 profile source file. */
export function basicDifficultyV2Policy(taskId: BasicDifficultyTaskId, mode: BasicDifficultyMode, manifest?: RuntimeManifest): BasicDifficultyPolicy {
  if (taskId === 'S1') return mode === 'ranked'
    ? { source: 'existing_ranked_reference_default', amountUnits: '100000' }
    : { source: 'existing_open_training_reference', amountUnits: '200000' };
  if (taskId === 'S2') return mode === 'ranked'
    ? { source: 'existing_ranked_reference_default', resourceId: manifest?.x402.resourceId ?? 'bef-resource-v1', offerId: 'canonical' }
    : { source: 'existing_open_training_reference', resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard' };
  if (taskId === 'S3') {
    if (mode !== 'ranked') throw new Error('task_difficulty_v2_s3_ranked_only');
    return { source: 'existing_ranked_reference_default', resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-extended' };
  }
  if (taskId === 'S4') return mode === 'ranked'
    ? { source: 'existing_ranked_reference_default', initialAllowanceUnits: '10000' }
    : { source: 'existing_open_training_reference', initialAllowanceUnits: '20000' };
  return mode === 'ranked'
    ? { source: 'existing_ranked_reference_default', amountUnits: '100000', publicExactQuote: false }
    : { source: 'existing_open_training_reference', amountUnits: '200000', publicExactQuote: true };
}

/** S3 preserves the existing scoped choice policy without asserting a paid-data validator. */
export function projectS3DifficultyV2Candidate(publicCatalog: PublicCatalogProjection): Record<string, unknown> {
  const requiredDataType = 'market-state-brief';
  const typed = publicCatalog.offers.filter((offer) => offer.dataType === requiredDataType);
  if (typed.length < 2) throw new Error('task_difficulty_v2_s3_catalog_scope_incomplete');
  const referenceOfferId = 'market-brief-extended';
  const reference = typed.find((offer) => offer.offerId === referenceOfferId);
  if (!reference) throw new Error('task_difficulty_v2_s3_reference_offer_missing');
  const first = typed[0]!;
  const eligible = typed.filter((offer) => offer.network === first.network && offer.assetId === first.assetId
    && offer.recipient.toLowerCase() === first.recipient.toLowerCase());
  if (!eligible.some((offer) => offer.offerId === referenceOfferId)) throw new Error('task_difficulty_v2_s3_reference_offer_not_eligible');
  const maximum = typed.reduce((value, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) > value
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : value, 0n).toString();
  return {
    schemaVersion: 'bts-s3-observed-catalog-objective-candidate/v2',
    classification: 'derived_from_actual_pinned_public_catalog_not_release_or_answer',
    required: {
      requiredDataType,
      maxAdvertisedTotalPriceUsdcUnits: maximum,
      network: first.network,
      assetId: first.assetId,
      recipient: first.recipient,
    },
    referenceAnswerCandidate: { offerId: reference.offerId, resourceId: reference.resourceId },
    eligibleOfferIds: eligible.map((offer) => offer.offerId),
    catalogOffers: publicCatalog.offers,
    deliveryValidation: 'not_asserted_for_free_catalog_inspection',
  };
}

type CapturedResponse = { kind: BasicDifficultyActionKind | 'fixture_setup_approve' | 'unclassified_actor_action'; operationId: string; rawResponsePath: string; rawResponseSha256: string };

function secretIn(ctx: ProbeContext, bytes: Uint8Array): boolean {
  const raw = Buffer.from(bytes);
  return ctx.secretValues.some((secret) => secret.length > 0 && raw.includes(Buffer.from(secret, 'utf8')));
}

async function recordActualResponse(ctx: ProbeContext, taskId: BasicDifficultyTaskId, kind: CapturedResponse['kind'], response: {
  operationId: string | null; body: unknown; rawBody: Buffer;
}): Promise<CapturedResponse> {
  const body = record(response.body);
  const operationId = response.operationId ?? (typeof body?.operationId === 'string' ? body.operationId : null);
  if (!operationId || !UUID.test(operationId)) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_operation_missing`);
  if (response.rawBody.byteLength === 0 || secretIn(ctx, response.rawBody)) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_raw_response_unavailable_or_secret`);
  }
  const rawResponsePath = `task-difficulty-v2/${taskId.toLowerCase()}/responses/${operationId}-${kind}.json`;
  await ctx.evidence.writeRawJson(rawResponsePath, response.rawBody, 'actual-tool-http');
  const rawResponseSha256 = sha256Bytes(response.rawBody);
  const written = ctx.evidence.artifacts.find((item) => item.path === rawResponsePath);
  if (!written || written.sha256 !== rawResponseSha256) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_raw_response_hash_mismatch`);
  return { kind, operationId, rawResponsePath, rawResponseSha256 };
}

async function withResponseCapture<T>(ctx: ProbeContext, taskId: BasicDifficultyTaskId,
  classify: (input: Parameters<ProbeContext['transport']['request']>[0]) => CapturedResponse['kind'] | null,
  action: () => Promise<T>): Promise<{ result: T; responses: CapturedResponse[] }> {
  const responses: CapturedResponse[] = [];
  const original = ctx.transport.request;
  ctx.transport.request = async (input) => {
    const response = await original.call(ctx.transport, input);
    if (input.boundary === 'actual-tool-http') {
      const kind = classify(input);
      if (kind) responses.push(await recordActualResponse(ctx, taskId, kind, response));
    }
    return response;
  };
  try {
    return { result: await action(), responses };
  } finally {
    ctx.transport.request = original;
  }
}

function safeTrace(responses: readonly CapturedResponse[]): BasicDifficultyAction[] {
  return responses.flatMap((item) => {
    if (item.kind === 'fixture_setup_approve' || item.kind === 'unclassified_actor_action') return [];
    return [{ kind: item.kind, operationId: item.operationId, rawResponsePath: item.rawResponsePath, rawResponseSha256: item.rawResponseSha256 }];
  });
}

function assertActionIds(actions: readonly BasicDifficultyAction[], expected: readonly unknown[], taskId: BasicDifficultyTaskId): void {
  if (actions.length !== expected.length || expected.some((value, index) => {
    const operationId = record(value)?.operationId ?? value;
    return typeof operationId !== 'string' || actions[index]?.operationId !== operationId;
  }) || new Set(actions.map((item) => item.operationId)).size !== actions.length) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_participant_action_binding_mismatch`);
  }
}

function sessionFor(ctx: ProbeContext, taskId: BasicDifficultyTaskId): GenerationSession {
  const session = ctx.primarySession;
  if (!session || !ctx.primaryGeneration || session.generationId !== ctx.primaryGeneration.generationId) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_generation_session_missing`);
  }
  return session;
}

async function writeCandidate(ctx: ProbeContext, taskId: BasicDifficultyTaskId, mode: BasicDifficultyMode,
  source: { path: string; sha256: string }, captureBody: Record<string, unknown>, operationId: string | null, variantId: string): Promise<{ path: string; sha256: string }> {
  const capture: Record<string, unknown> = { ...captureBody, taskId, mode, releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true };
  capture.caseHash = canonicalSha256(capture);
  const path = `task-difficulty-v2/candidates/${taskId.toLowerCase()}-${mode}.json`;
  await ctx.evidence.writeObservation(path, `difficulty-v2-${taskId.toLowerCase()}-${mode}-candidate`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId, variantId,
    difficultyProfileEvidence: { profileId: 'bts-task-difficulty-v2', path: source.path, sha256: source.sha256,
      manifestSha256: ctx.runtime.manifestSha256 },
    candidate: sanitizeValue(capture, ctx.secretValues),
  });
  const artifact = ctx.evidence.artifacts.find((item) => item.path === path);
  if (!artifact) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_candidate_artifact_missing`);
  return { path: artifact.path, sha256: artifact.sha256 };
}

function s3Objective(publicCatalog: PublicCatalogProjection): Record<string, unknown> {
  return projectS3DifficultyV2Candidate(publicCatalog);
}

function findOffer(manifest: RuntimeManifest, resourceId: string, offerId: string): { amount: string } {
  const resources = manifest.x402.catalog?.filter((item) => item.resourceId === resourceId) ?? [];
  const resource = resources.length === 1 ? resources[0] : undefined;
  const offers = resource?.offers.filter((item) => item.id === offerId) ?? [];
  const offer = offers.length === 1 ? offers[0] : undefined;
  if (!resource || !offer) throw new Error('task_difficulty_v2_s2_manifest_offer_missing');
  return { amount: offer.amount };
}

async function captureS3(ctx: ProbeContext, mode: BasicDifficultyMode, source: { path: string; sha256: string }): Promise<BasicDifficultyCapture> {
  if (mode !== 'ranked') throw new Error('task_difficulty_v2_s3_ranked_only');
  const policy = basicDifficultyV2Policy('S3', mode, ctx.runtime.manifest);
  const variantId = 'bts_s3_ranked_difficulty_v2_split_reference';
  const session = await startFreshCaseGeneration(ctx, { caseId: 's3', scenarioId: 'BEF-SC-004', variantId });
  const baseline = await readCaseDatabaseFacts(ctx, session, `${variantId}-baseline`, variantId);
  if (baseline.operations.length || baseline.payments.length || baseline.deliveries.length) {
    throw new Error('task_difficulty_v2_s3_generation_baseline_not_clean');
  }
  const blockBefore = await latestBlock(ctx, null, variantId, `${variantId}-before`);
  const initialState = await readCaseState(ctx, { session, blockTag: blockBefore.tag, blockHash: blockBefore.hash,
    operationId: null, variantId, label: `${variantId}-state-before` });
  const read = await inspectSplitCatalog(ctx, session, { variantId, label: variantId });
  const publicCatalog = read.catalogProjection;
  if (!publicCatalog) throw new Error('task_difficulty_v2_s3_public_catalog_projection_missing');
  const candidate = s3Objective(publicCatalog);
  const stateAfter = await readCaseState(ctx, { session, blockTag: blockBefore.tag, blockHash: blockBefore.hash,
    operationId: read.operationId, variantId, label: `${variantId}-state-after` });
  const blockAfter = await latestBlock(ctx, read.operationId, variantId, `${variantId}-after`);
  const facts = await readCaseDatabaseFacts(ctx, session, `${variantId}-final-database`, variantId);
  const catalogRows = facts.operations.filter((row) => row.operation_kind === 'catalog' && String(row.operation_id) === read.operationId);
  if (blockBefore.number !== blockAfter.number || blockBefore.hash !== blockAfter.hash
    || JSON.stringify(initialState) !== JSON.stringify(stateAfter)
    || facts.operations.length !== 1 || facts.counts.operations !== '1' || facts.counts.payments !== '0' || facts.counts.deliveries !== '0'
    || facts.counts.denials !== '0' || facts.counts.transactionCosts !== '0' || catalogRows.length !== 1
    || catalogRows[0]!.status !== 'accepted' || catalogRows[0]!.receipt_status !== 'not_submitted') {
    throw new Error('task_difficulty_v2_s3_catalog_read_only_boundary_mismatch');
  }
  if (read.participantAction.kind !== 'inspect_catalog') throw new Error('task_difficulty_v2_s3_catalog_action_kind_invalid');
  const participantActions: BasicDifficultyAction[] = [{ ...read.participantAction, kind: 'inspect_catalog' }];
  const capture: Record<string, unknown> = {
    schemaVersion: 'bts-s3-difficulty-v2-reference/v1', classification: 'local_fork_reference_candidate_not_bts_acceptance',
    status: 'observed_candidate', taskId: 'S3', mode,
    difficultyProfile: { profileId: 'bts-task-difficulty-v2', mode, sourcePath: source.path,
      sourceSha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    inputPolicy: { ...policy, participantActionPlan: ['inspect_catalog'], countedParticipantActions: 1 },
    participantToolProtocol: 'separate_payment_delivery_v2', participantActionPlan: ['inspect_catalog'],
    countedParticipantActions: 1, participantActions, environment: { envId: session.envId, generationId: session.generationId,
      participantId: session.participantId, payerAddress: session.payerAddress.toLowerCase() },
    publicCatalog: { operationId: read.operationId, rawResponsePath: read.rawResponsePath,
      rawResponseSha256: read.rawResponseSha256, response: publicCatalog },
    objectiveCandidate: candidate,
    initialState, finalState: stateAfter,
    initialDatabaseCounts: { operations: String(baseline.counts.operations), payments: String(baseline.counts.payments), deliveries: String(baseline.counts.deliveries) },
    durableDatabase: { counts: facts.counts, operations: facts.operations, payments: facts.payments, deliveries: facts.deliveries,
      transactionCosts: facts.transactionCosts },
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  const caseArtifact = await writeCandidate(ctx, 'S3', mode, source, capture, read.operationId, variantId);
  return { taskId: 'S3', mode, capture, session, participantActions, caseArtifact };
}

async function captureNative(ctx: ProbeContext, taskId: 'S4' | 'M3', mode: BasicDifficultyMode,
  source: { path: string; sha256: string }): Promise<BasicDifficultyCapture> {
  const policy = basicDifficultyV2Policy(taskId, mode, ctx.runtime.manifest);
  const variantId = `bts_${taskId.toLowerCase()}_${mode}_difficulty_v2_native_reference`;
  const classify = (input: Parameters<ProbeContext['transport']['request']>[0]): CapturedResponse['kind'] | null => {
    let pathname = '';
    try { pathname = new URL(input.url).pathname; } catch { return null; }
    const actionRoute = input.method.toUpperCase() === 'POST' && [
      `/tools/${ctx.env.envId}/approve`, `/tools/${ctx.env.envId}/swap`, `/tools/${ctx.env.envId}/unwrap`,
    ].includes(pathname);
    if (!actionRoute) return null;
    if (taskId === 'S4') {
      if (input.observationId === 'task-native-s4-fixture-setup-approve') return 'fixture_setup_approve';
      if (input.observationId === 'task-native-s4-task-revoke-allowance') return 'revoke';
      return 'unclassified_actor_action';
    }
    if (input.observationId === 'task-native-m3-approve-usdc') return 'approve';
    if (input.observationId === 'task-native-m3-usdc-to-weth') return 'swap';
    if (input.observationId === 'task-native-m3-unwrap-weth') return 'unwrap';
    return 'unclassified_actor_action';
  };
  const native = await withResponseCapture(ctx, taskId, classify, () => captureS4M3M4(ctx, policy.amountUnits ?? '100000', {
    tasks: [taskId], ...(policy.publicExactQuote !== undefined ? { usePublicExactQuote: policy.publicExactQuote } : {}),
    ...(policy.initialAllowanceUnits ? { s4InitialAllowanceUnits: policy.initialAllowanceUnits } : {}),
  }));
  const session = sessionFor(ctx, taskId);
  const captures = record(native.result.captures);
  const legacyCapture = record(captures?.[taskId]);
  const actionReferences = native.responses;
  if (actionReferences.some((item) => item.kind === 'unclassified_actor_action')) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_unclassified_tool_action`);
  }
  const participantActions = safeTrace(actionReferences);
  if (!legacyCapture) throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_native_capture_missing`);
  let expectedIds: unknown[];
  let operationId: string | null = null;
  let fixtureSetup: Record<string, unknown> | null = null;
  if (taskId === 'S4') {
    fixtureSetup = record(legacyCapture.fixtureSetup);
    const taskPath = record(legacyCapture.taskPath);
    expectedIds = [taskPath];
    operationId = typeof taskPath?.operationId === 'string' ? taskPath.operationId : null;
    const setupRecord = actionReferences.find((item) => item.kind === 'fixture_setup_approve');
    if (!fixtureSetup || !setupRecord || actionReferences.filter((item) => item.kind === 'fixture_setup_approve').length !== 1
      || setupRecord.operationId !== fixtureSetup.operationId) {
      throw new Error('task_difficulty_v2_s4_fixture_setup_raw_evidence_missing');
    }
    fixtureSetup = { ...fixtureSetup, rawResponsePath: setupRecord.rawResponsePath, rawResponseSha256: setupRecord.rawResponseSha256 };
  } else {
    const legacyActions = record(legacyCapture.actions);
    expectedIds = [record(legacyActions?.approval), record(legacyActions?.swap), record(legacyActions?.unwrap)];
    operationId = typeof record(legacyActions?.unwrap)?.operationId === 'string' ? String(record(legacyActions?.unwrap)?.operationId) : null;
  }
  assertActionIds(participantActions, expectedIds, taskId);
  const expectedKinds: BasicDifficultyActionKind[] = taskId === 'S4' ? ['revoke'] : ['approve', 'swap', 'unwrap'];
  if (participantActions.some((action, index) => action.kind !== expectedKinds[index])) {
    throw new Error(`task_difficulty_v2_${taskId.toLowerCase()}_participant_action_order_invalid`);
  }
  const capture: Record<string, unknown> = {
    schemaVersion: `bts-${taskId.toLowerCase()}-difficulty-v2-reference/v1`,
    classification: 'local_fork_reference_candidate_not_bts_acceptance', status: 'observed_candidate', taskId, mode,
    difficultyProfile: { profileId: 'bts-task-difficulty-v2', mode, sourcePath: source.path,
      sourceSha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    inputPolicy: { ...policy, participantActionPlan: expectedKinds, countedParticipantActions: expectedKinds.length },
    participantToolProtocol: 'separate_payment_delivery_v2',
    ...(taskId === 'S4' || taskId === 'M3' ? { executionProtocol: 'selected_execution_v1' } : {}),
    participantActionPlan: expectedKinds,
    countedParticipantActions: participantActions.length, participantActions,
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId,
      payerAddress: session.payerAddress.toLowerCase() },
    ...(taskId === 'S4' ? { fixtureSetup: { ...fixtureSetup, outsideParticipantPath: true } } : {}),
    referenceCapture: legacyCapture,
    ...(actionReferences.filter((item) => item.kind === 'fixture_setup_approve').length
      ? { fixtureStageEvidence: actionReferences.filter((item) => item.kind === 'fixture_setup_approve') } : {}),
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  const caseArtifact = await writeCandidate(ctx, taskId, mode, source, capture, operationId, variantId);
  return { taskId, mode, capture, session, participantActions, caseArtifact };
}

async function captureS1(ctx: ProbeContext, mode: BasicDifficultyMode, source: { path: string; sha256: string }, recipient?: string): Promise<BasicDifficultyCapture> {
  const policy = basicDifficultyV2Policy('S1', mode, ctx.runtime.manifest);
  const variantId = `bts_s1_${mode}_difficulty_v2_transfer_reference`;
  const { result: legacyCapture, responses } = await withResponseCapture(ctx, 'S1', (input) => {
    let pathname = '';
    try { pathname = new URL(input.url).pathname; } catch { return null; }
    if (input.method.toUpperCase() === 'POST' && pathname === `/tools/${ctx.env.envId}/transfer`) return 'transfer';
    return 'unclassified_actor_action';
  }, () => captureSelectedUsdcTransfer(ctx, policy.amountUnits, recipient));
  const session = sessionFor(ctx, 'S1');
  if (responses.some((item) => item.kind === 'unclassified_actor_action')) throw new Error('task_difficulty_v2_s1_unclassified_tool_action');
  const operation = record(legacyCapture.operation);
  const actions: BasicDifficultyAction[] = safeTrace(responses);
  assertActionIds(actions, [operation], 'S1');
  if (actions.length !== 1 || actions[0]!.kind !== 'transfer') throw new Error('task_difficulty_v2_s1_participant_action_trace_invalid');
  const capture: Record<string, unknown> = {
    ...legacyCapture,
    schemaVersion: 'bts-s1-difficulty-v2-reference/v1', classification: 'local_fork_reference_candidate_not_bts_acceptance',
    taskId: 'S1', mode, difficultyProfile: { profileId: 'bts-task-difficulty-v2', mode, sourcePath: source.path,
      sourceSha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    inputPolicy: { ...policy, participantActionPlan: ['transfer'], countedParticipantActions: 1 },
    recipientSelection: recipient === undefined ? { source: 'ephemeral_generator' }
      : { source: 'explicit_public_fixture', recipient },
    participantToolProtocol: 'separate_payment_delivery_v2', executionProtocol: 'selected_execution_v1', participantActionPlan: ['transfer'],
    countedParticipantActions: actions.length, participantActions: actions,
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  const caseArtifact = await writeCandidate(ctx, 'S1', mode, source, capture, actions[0]!.operationId, variantId);
  return { taskId: 'S1', mode, capture, session, participantActions: actions, caseArtifact };
}

async function captureS2(ctx: ProbeContext, mode: BasicDifficultyMode, source: { path: string; sha256: string }): Promise<BasicDifficultyCapture> {
  const policy = basicDifficultyV2Policy('S2', mode, ctx.runtime.manifest);
  const resourceId = requiredString(policy.resourceId, 's2_resource_id');
  const offerId = requiredString(policy.offerId, 's2_offer_id');
  const { amount } = findOffer(ctx.runtime.manifest, resourceId, offerId);
  const variantId = `bts_s2_${mode}_difficulty_v2_offer_reference`;
  const { result: legacyCapture, responses } = await withResponseCapture(ctx, 'S2', (input) => {
    let url: URL;
    try { url = new URL(input.url); } catch { return null; }
    if (input.method.toUpperCase() === 'GET' && url.pathname === `/tools/${ctx.env.envId}/offer`
      && url.searchParams.get('resourceId') === resourceId) return 'inspect_offer';
    return 'unclassified_actor_action';
  }, () => captureS2ReadonlyOffer(ctx, { resourceId, expectedOfferId: offerId, variantId }));
  const session = sessionFor(ctx, 'S2');
  if (responses.some((item) => item.kind === 'unclassified_actor_action')) throw new Error('task_difficulty_v2_s2_unclassified_tool_action');
  const interval = record(legacyCapture.noEffectInterval);
  const operation = record(interval?.offerReadOperation);
  const actions = safeTrace(responses);
  assertActionIds(actions, [operation], 'S2');
  const objective = record(legacyCapture.objectiveCandidate);
  if (amount !== (record(objective?.completePaymentRequirements)?.amountUnits)
    || objective?.resourceId !== resourceId || objective.offerId !== offerId || actions.length !== 1 || actions[0]!.kind !== 'inspect_offer') {
    throw new Error('task_difficulty_v2_s2_observed_offer_policy_mismatch');
  }
  const capture: Record<string, unknown> = {
    ...legacyCapture,
    schemaVersion: 'bts-s2-difficulty-v2-reference/v1', classification: 'local_fork_reference_candidate_not_bts_acceptance',
    taskId: 'S2', mode, difficultyProfile: { profileId: 'bts-task-difficulty-v2', mode, sourcePath: source.path,
      sourceSha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    inputPolicy: { ...policy, amountUnits: amount, participantActionPlan: ['inspect_offer'], countedParticipantActions: 1 },
    participantToolProtocol: 'separate_payment_delivery_v2', participantActionPlan: ['inspect_offer'],
    countedParticipantActions: actions.length, participantActions: actions,
    releaseReadiness: 'blocked', candidateDoesNotClaimTaskScore: true,
  };
  const caseArtifact = await writeCandidate(ctx, 'S2', mode, source, capture, actions[0]!.operationId, variantId);
  return { taskId: 'S2', mode, capture, session, participantActions: actions, caseArtifact };
}

export async function captureBasicDifficultyV2Task(ctx: ProbeContext, input: {
  taskId: BasicDifficultyTaskId; mode: BasicDifficultyMode; source: { path: string; sha256: string };
  recipient?: string;
}): Promise<BasicDifficultyCapture> {
  if (input.taskId === 'S1') return captureS1(ctx, input.mode, input.source, input.recipient);
  if (input.taskId === 'S2') return captureS2(ctx, input.mode, input.source);
  if (input.taskId === 'S3') return captureS3(ctx, input.mode, input.source);
  if (input.taskId === 'S4' || input.taskId === 'M3') return captureNative(ctx, input.taskId, input.mode, input.source);
  throw new Error('task_difficulty_v2_basic_task_not_supported');
}
