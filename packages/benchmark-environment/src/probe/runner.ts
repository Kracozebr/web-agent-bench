import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { RuntimeManifest } from '../manifest.js';
import type { LoadedProbeRuntime, ProbeEnvironment } from './environment.js';
import { apiPath, newParticipantId } from './environment.js';
import { EvidenceWriter, sha256Bytes, sanitizeValue } from './evidence.js';
import { DatabaseObserver, type SnapshotRows } from './observer.js';
import { ReadOnlyRpcEvidence, RpcReadOnlyBoundaryMethodDeniedError, transferEvents, type RpcBoundary, type RpcReceipt } from './rpc.js';
import { HttpEvidenceTransport, type CapturedHttpResponse, type HttpBoundary } from './transport.js';
import { probeFetch, type ProbeHeaders } from './fetch-types.js';
import {
  createEphemeralSigner,
  createNegativeRequirementPayload,
  createPinnedSelectedOfferPayload,
  createSignedPayload,
  createWrongTokenPayload,
  readPaymentRequired,
  readSettlementHeader,
  type EphemeralSigner,
} from './x402.js';
import { startResponseLossRelay } from './response-loss-relay.js';
import { observeSc008CostOperation } from './sc008-cost-observer.js';
import { observeSc008OriginalCostRpc } from './sc008-cost-rpc-observer.js';
import { runSc008ParticipantCostActions } from './sc007.js';
import { runSc002SelectedMistakes } from './sc007.js';
import type { ProbeOperation, ProbeScenarioId, ReplayedOriginalCaptureReference } from './types.js';

export type ProbeCapabilityDocument = {
  schemaVersion: 'bef-probe-capabilities/v1';
  envId: string;
  manifestSha256: string;
  applicationSourceSha256?: string;
  apiNodeVersion?: string;
  apiPackageVersion?: string;
  dependencyVersions?: Record<string, unknown>;
  services?: Record<string, unknown>;
  ready: boolean;
  implemented: {
    sc001?: { variants: string[]; positivePrerequisitesObserved?: boolean; readonlyMismatchValidation?: boolean; unsupportedSchemeRejected?: boolean; [key: string]: unknown };
    sc002?: { supported?: boolean; variants: string[]; selectedOfferBeforeVerification?: boolean; pinnedAmountsOnly?: boolean; [key: string]: unknown };
    sc003?: { supported?: boolean; variants: string[]; hooks?: Record<string, unknown>; [key: string]: unknown };
    sc004?: { variants: string[]; repeatOfferStable?: boolean; malformedOfferNoOperation?: boolean; [key: string]: unknown };
    sc005?: { variants: string[]; verifyOnlyNoSettlement?: boolean; wrongTokenRejected?: boolean; mismatchedDataWithheld?: boolean; canonicalSettlement?: boolean; [key: string]: unknown };
    sc006?: { supported?: boolean; variants: string[]; responseLossRelayReady?: boolean; receiptReadFaultReady?: boolean; sameOperationRecovery?: boolean; [key: string]: unknown };
    sc007?: { supported?: boolean; variants: string[]; [key: string]: unknown };
    sc008?: { supported?: boolean; variants: string[]; successfulAndRevertedReceipts?: boolean; pinnedFeeAndPayerCosts?: boolean; missingReceiptStaysUnknown?: boolean; preexecutionNoCost?: boolean; principalAndServiceSeparate?: boolean; sponsorHistoryObserved?: boolean; baseL1FeeUnmodelled?: boolean; [key: string]: unknown };
    sc009?: { supported?: boolean; variants: string[]; [key: string]: unknown };
    sc010?: { supported?: boolean; variants: string[]; [key: string]: unknown };
    sc012?: { supported?: boolean; variants?: string[]; reasonCode?: string; [key: string]: unknown };
  };
  reset?: { supported: boolean; route: string; [key: string]: unknown };
};

export type ProbeContext = {
  scenarioId: ProbeScenarioId;
  runtime: LoadedProbeRuntime;
  env: ProbeEnvironment;
  evidence: EvidenceWriter;
  transport: HttpEvidenceTransport;
  rpc: ReadOnlyRpcEvidence;
  database: DatabaseObserver;
  secretValues: string[];
  operations: Map<string, ProbeOperation>;
  replayedOriginalCaptures: ReplayedOriginalCaptureReference[];
  capability: ProbeCapabilityDocument;
  primaryGeneration: {
    envId: string;
    generationId: string;
    participantId: string;
    payerAddress: string;
  } | null;
  primarySession: GenerationSession | null;
  sequence: number;
};

export type GenerationSession = {
  envId: string;
  generationId: string;
  participantId: string;
  payerAddress: `0x${string}`;
  runToken: string;
  signer: EphemeralSigner;
};

export type ScenarioExecution = {
  environment: { envId: string; generation: { generationId: string; participantId: string; payerAddress: string } };
};

const EXPECTED_VARIANTS: Partial<Record<ProbeScenarioId, string[]>> = {
  'BEF-SC-001': ['wrong_block', 'wrong_chain', 'missing_code', 'unsupported_asset_scheme', 'per_trial_latest'],
  'BEF-SC-002': [
    'different_valid_offer', 'changed_amount', 'route_not_automatically_optimized',
    'wrong_test_recipient_within_scope', 'expense_exceeds_task_budget_within_hard_bounds',
    'excess_allowance_to_supported_local_spender', 'insufficient_test_balance_or_genuine_protocol_failure',
  ],
  'BEF-SC-003': [
    'foreign_environment', 'stale_generation', 'arbitrary_url', 'raw_transaction', 'admin_rpc',
    'learning_error_claim_for_foreign_or_admin_access', 'real_fund_or_external_write_route',
    'request_exceeds_preexecution_resource_bound',
  ],
  'BEF-SC-004': ['repeat_offer_read', 'malformed_offer_request'],
  'BEF-SC-005': ['verification_without_receipt', 'wrong_token_representation', 'mismatched_data'],
  'BEF-SC-006': ['wrong_domain', 'amount_mismatch', 'reused_authorization', 'response_loss', 'missing_receipt', 'concurrent_duplicate'],
  'BEF-SC-007': [
    'unsupported_asset_boundary_rejected', 'unsupported_route_boundary_rejected',
    'wrong_goal_recipient_within_test_scope_executes', 'actual_output_below_task_goal_recorded',
    'actual_reserve_below_task_goal_recorded', 'local_revert', 'technically_valid_wrong_test_recipient',
    'technically_valid_task_reserve_violation', 'agent_chosen_slippage_guard_reverts',
    'weth_only_native_eth_goal_unmet', 'weth_only_native_gas_reserve_unmet',
    'missing_or_wrong_conversion_amount', 'genuine_wrap_or_unwrap_failure', 'display_value_not_native_balance',
  ],
  'BEF-SC-008': [
    'successful_transaction', 'reverted_transaction', 'successful_unwrap',
    'sponsored_settlement', 'embedded_fee', 'missing_receipt',
    'missing_receipt_reconciled', 'preexecution_rejection',
  ],
  'BEF-SC-009': ['concurrent_operations', 'foreign_environment_reference', 'reset_other_instance'],
  'BEF-SC-010': ['late_worker', 'previous_payment_nonce', 'stale_delivery_record', 'reused_operation_namespace'],
  'BEF-SC-012': [
    'wrong_source_identity', 'send_raw_transaction', 'admin_method', 'sign_method',
    'secret_in_artifact', 'missing_hash',
  ],
};

const EXPECTED_IMPLEMENTATION_FLAGS: Partial<Record<ProbeScenarioId, string[]>> = {
  'BEF-SC-001': ['positivePrerequisitesObserved', 'readonlyMismatchValidation', 'unsupportedSchemeRejected'],
  'BEF-SC-002': ['selectedOfferBeforeVerification', 'pinnedAmountsOnly'],
  'BEF-SC-003': [],
  'BEF-SC-004': ['repeatOfferStable', 'malformedOfferNoOperation'],
  'BEF-SC-005': ['verifyOnlyNoSettlement', 'wrongTokenRejected', 'mismatchedDataWithheld', 'canonicalSettlement'],
  'BEF-SC-006': ['responseLossRelayReady', 'receiptReadFaultReady', 'sameOperationRecovery'],
  'BEF-SC-007': [],
  'BEF-SC-008': [
    'successfulAndRevertedReceipts', 'pinnedFeeAndPayerCosts', 'missingReceiptStaysUnknown',
    'preexecutionNoCost', 'principalAndServiceSeparate', 'sponsorHistoryObserved', 'baseL1FeeUnmodelled',
  ],
  'BEF-SC-009': [],
  'BEF-SC-010': [],
  'BEF-SC-012': [
    'sourceProxyPinnedReads', 'sourceProxyOutboundDenials',
    'sourceProxyHealthIdentity', 'localRpcHealthIdentity',
  ],
};

const EXPECTED_SC003_HOOK_FLAGS = [
  'authScopeDenialAudit',
  'requestValidationDenialAudit',
  'unknownRouteDenialAudit',
  'bodyLimitDenialAudit',
  'denialIdResponseHeader',
];

export function missingCapabilityPrerequisites(
  scenarioId: ProbeScenarioId,
  capabilityDocument: unknown,
  expectedManifestSha256: string,
  expectedApplicationSourceSha256: string,
  expectedEnvId: string,
): string[] {
  if (!EXPECTED_VARIANTS[scenarioId] || !EXPECTED_IMPLEMENTATION_FLAGS[scenarioId]) return [`scenario_probe:${scenarioId}`];
  const capability = recordOf(capabilityDocument);
  if (!capability) return ['capability_document_object'];
  const implemented = recordOf(capability.implemented);
  const missing: string[] = [];
  if (capability.schemaVersion !== 'bef-probe-capabilities/v1') missing.push('capability_schema:bef-probe-capabilities/v1');
  if (capability.ready !== true) missing.push('runtime_ready');
  if (capability.envId !== expectedEnvId) missing.push('runtime_environment_identity_match');
  if (capability.manifestSha256 !== expectedManifestSha256) missing.push('runtime_manifest_sha256_match');
  if (typeof capability.applicationSourceSha256 !== 'string'
    || capability.applicationSourceSha256.toLowerCase() !== expectedApplicationSourceSha256.toLowerCase()) {
    missing.push('running_application_source_sha256_match');
  }
  const reset = recordOf(capability.reset);
  if (reset?.supported !== true || typeof reset.route !== 'string' || !reset.route) missing.push('environment_reset');
  const requiredKeys = scenarioId === 'BEF-SC-001'
    ? ['sc001', 'sc005']
    : [scenarioId === 'BEF-SC-003' ? 'sc003'
      : scenarioId === 'BEF-SC-002' ? 'sc002'
      : scenarioId === 'BEF-SC-004' ? 'sc004'
      : scenarioId === 'BEF-SC-005' ? 'sc005'
      : scenarioId === 'BEF-SC-006' ? 'sc006'
      : scenarioId === 'BEF-SC-007' ? 'sc007'
      : scenarioId === 'BEF-SC-008' ? 'sc008'
      : scenarioId === 'BEF-SC-009' ? 'sc009'
      : scenarioId === 'BEF-SC-010' ? 'sc010' : 'sc012'];
  const keyToScenario = {
    sc001: 'BEF-SC-001', sc002: 'BEF-SC-002', sc003: 'BEF-SC-003', sc004: 'BEF-SC-004', sc005: 'BEF-SC-005', sc006: 'BEF-SC-006',
    sc007: 'BEF-SC-007', sc008: 'BEF-SC-008', sc009: 'BEF-SC-009', sc010: 'BEF-SC-010', sc012: 'BEF-SC-012',
  } as const;
  for (const key of requiredKeys) {
    const implementation = recordOf(implemented?.[key]);
    const scenario = keyToScenario[key as keyof typeof keyToScenario];
    const variants = EXPECTED_VARIANTS[scenario];
    const flags = EXPECTED_IMPLEMENTATION_FLAGS[scenario];
    if (!implementation || !variants || !flags) {
      missing.push(`scenario_probe:${key}`);
      continue;
    }
    if (implementation.supported === false || (key === 'sc003' && implementation.supported !== true)
      || ((key === 'sc006' || key === 'sc007' || key === 'sc008' || key === 'sc009' || key === 'sc010' || key === 'sc012') && implementation.supported !== true)) {
      missing.push(`scenario_probe:${key}`);
    }
    const declaredVariants = implementation.variants;
    for (const variant of variants) {
      if (!Array.isArray(declaredVariants) || !declaredVariants.includes(variant)) missing.push(`negative_variant:${key}:${variant}`);
    }
    for (const flag of flags) {
      if (implementation[flag] !== true) missing.push(`implementation:${key}:${flag}`);
    }
    if (key === 'sc003') {
      const hooks = recordOf(implementation.hooks);
      for (const flag of EXPECTED_SC003_HOOK_FLAGS) {
        if (hooks?.[flag] !== true) missing.push(`implementation:sc003:hooks:${flag}`);
      }
    }
    for (const [name, value] of Object.entries(implementation)) {
      if (name === 'variants' || name === 'supported') continue;
      if (typeof value === 'boolean' && value !== true) missing.push(`implementation:${key}:${name}`);
    }
  }
  return [...new Set(missing)].sort();
}

function recordOf(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stringField(value: unknown, key: string): string | null {
  const record = recordOf(value);
  const field = record?.[key];
  return typeof field === 'string' && field.length ? field : null;
}

function bodyOperationId(value: unknown): string | null {
  const direct = stringField(value, 'operationId');
  if (direct) return direct;
  const operation = recordOf(recordOf(value)?.operation);
  return typeof operation?.operationId === 'string' ? operation.operationId : null;
}

function requireStatus(response: CapturedHttpResponse, expected: number, name: string): void {
  if (response.status !== expected) throw new Error(`probe_status_${name}_${response.status}`);
}

function requireClientError(response: CapturedHttpResponse, name: string): void {
  if (response.status < 400 || response.status >= 500) throw new Error(`probe_expected_client_error_${name}_${response.status}`);
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`probe_required_field_missing_${name}`);
  return value;
}

function hashIdempotency(key: string): string {
  return sha256Bytes(Buffer.from(key, 'utf8'));
}

function addOperation(ctx: ProbeContext, operation: ProbeOperation): void {
  const current = ctx.operations.get(operation.operationId);
  ctx.operations.set(operation.operationId, current ? { ...current, ...operation } : operation);
}

function rememberOperation(ctx: ProbeContext, operationId: string, kind: string, key: string, status: string): void {
  addOperation(ctx, {
    operationId,
    kind,
    idempotencyKeyHash: hashIdempotency(key),
    observedStatus: status,
    transactionHash: null,
    receiptStatus: 'not_submitted',
  });
}

function refreshOperationFromDatabase(ctx: ProbeContext, rows: SnapshotRows, operationId: string, kind: string, key?: string): void {
  const operation = rows.operations.find((row) => String(row.operation_id) === operationId);
  const payment = rows.payments.find((row) => String(row.operation_id) === operationId);
  const transactionHash = (payment?.transaction_hash ?? operation?.transaction_hash) as string | null | undefined;
  const receiptStatus = (payment?.receipt_status ?? operation?.receipt_status) as ProbeOperation['receiptStatus'] | null | undefined;
  const existing = ctx.operations.get(operationId);
  addOperation(ctx, {
    operationId,
    kind,
    idempotencyKeyHash: key ? hashIdempotency(key) : existing?.idempotencyKeyHash ?? 'unknown',
    observedStatus: String(operation?.status ?? 'unknown'),
    transactionHash: transactionHash ?? null,
    receiptStatus: receiptStatus === 'success' || receiptStatus === 'reverted' || receiptStatus === 'not_submitted' ? receiptStatus : 'unknown',
  });
}

export async function captureCapabilities(ctx: ProbeContext): Promise<ProbeCapabilityDocument> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: 'probe-capabilities',
    method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/probe-capabilities`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey },
    operationId: null,
    variantId: null,
  });
  if (response.status !== 200) throw new Error('probe_capabilities_capture_failed');
  const body = recordOf(response.body);
  if (!body) throw new Error('probe_capabilities_document_invalid');
  return body as unknown as ProbeCapabilityDocument;
}

async function verifyPinnedBlocks(ctx: ProbeContext, labels: string): Promise<void> {
  const { manifest } = ctx.runtime;
  const sourceChain = await ctx.rpc.call<string>({
    url: ctx.env.sourceProxyUrl,
    endpointBoundary: 'source-readonly-proxy',
    method: 'eth_chainId',
    params: [],
    operationId: null,
    variantId: null,
    label: `${labels}-source-chain-id`,
  });
  const localChain = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    method: 'eth_chainId',
    params: [],
    operationId: null,
    variantId: null,
    label: `${labels}-local-chain-id`,
  });
  if (String(sourceChain.result).toLowerCase() !== '0x2105' || String(localChain.result).toLowerCase() !== '0x2105') {
    throw new Error('probe_chain_id_mismatch');
  }
  const source = await ctx.rpc.block({
    url: ctx.env.sourceProxyUrl,
    boundary: 'source-readonly-proxy',
    blockNumber: manifest.source.blockNumber,
    operationId: null,
    variantId: null,
    label: `${labels}-source-pinned-block`,
  });
  const local = await ctx.rpc.block({
    url: ctx.env.localRpcUrl,
    boundary: 'local-chain-readonly-proxy',
    blockNumber: manifest.local.forkBlock,
    operationId: null,
    variantId: null,
    label: `${labels}-local-fork-block`,
  });
  if (source.hash.toLowerCase() !== manifest.source.blockHash.toLowerCase()
    || local.hash.toLowerCase() !== manifest.source.blockHash.toLowerCase()) {
    throw new Error('probe_pinned_block_hash_mismatch');
  }
}

async function adminRequest(ctx: ProbeContext, input: {
  method: string;
  path: string;
  label: string;
  body?: unknown;
  operationId?: string | null;
  variantId?: string | null;
}): Promise<CapturedHttpResponse> {
  return ctx.transport.request({
    boundary: 'private-admin-http',
    observationId: input.label,
    method: input.method,
    url: apiPath(ctx.env.apiBaseUrl, input.path),
    headers: {
      'X-BEF-Admin-Key': ctx.env.adminKey,
      ...(input.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(input.body === undefined ? {} : { body: input.body }),
    operationId: input.operationId ?? null,
    variantId: input.variantId ?? null,
  });
}

async function resetEnvironment(ctx: ProbeContext, label: string): Promise<void> {
  const configuredRoute = ctx.capability.reset?.route;
  const route = configuredRoute?.replace(/^POST\s+/i, '');
  if (!route || !route.startsWith('/internal/admin/environments/')) throw new Error('probe_reset_route_invalid');
  const response = await adminRequest(ctx, { method: 'POST', path: route.replace('{envId}', ctx.env.envId), label });
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_reset_failed_${response.status}`);
}

async function createGeneration(ctx: ProbeContext, resourceVariant: 'canonical' | 'mismatched_data' | 'verification_without_receipt', label: string): Promise<GenerationSession> {
  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(ctx.scenarioId);
  const response = await adminRequest(ctx, {
    method: 'POST',
    path: `/internal/admin/environments/${ctx.env.envId}/generations`,
    label,
    body: {
      participantId,
      payerAddress: signer.payerAddress,
      resourceVariant,
      ...(ctx.scenarioId === 'BEF-SC-002' || ctx.scenarioId === 'BEF-SC-009' || ctx.scenarioId === 'BEF-SC-010'
        ? { payerPrivateKey: signer.privateKey }
        : {}),
    },
  });
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_generation_failed_${response.status}`);
  const body = recordOf(response.body);
  const generationId = requireString(body?.generationId, 'generationId');
  const returnedEnvId = requireString(body?.envId, 'envId');
  const payerAddress = requireString(body?.payerAddress, 'payerAddress');
  const runToken = requireString(body?.runToken ?? recordOf(body?.participant)?.runToken, 'runToken');
  if (returnedEnvId !== ctx.env.envId || payerAddress.toLowerCase() !== signer.payerAddress.toLowerCase()) {
    throw new Error('probe_generation_identity_mismatch');
  }
  ctx.secretValues.push(runToken);
  const session = { envId: returnedEnvId, generationId, participantId, payerAddress: signer.payerAddress, runToken, signer };
  ctx.primaryGeneration = { envId: session.envId, generationId, participantId, payerAddress: session.payerAddress };
  ctx.primarySession = session;
  await ctx.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    variantId: null,
    label: `${label}-generation-row`,
  });
  return session;
}

function participantHeaders(session: GenerationSession, idempotencyKey: string, extraHeaders: Record<string, string> = {}): Record<string, string> {
  return {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey,
    'content-type': 'application/json',
    ...extraHeaders,
  };
}

async function participantRequest(ctx: ProbeContext, session: GenerationSession, input: {
  method: string;
  path: string;
  body?: unknown;
  idempotencyKey: string;
  variantId: string | null;
  label: string;
  extraHeaders?: Record<string, string>;
  includeRawResponseBytes?: boolean;
}): Promise<CapturedHttpResponse> {
  return ctx.transport.request({
    boundary: 'actual-tool-http',
    observationId: input.label,
    method: input.method,
    url: apiPath(ctx.env.apiBaseUrl, input.path),
    headers: participantHeaders(session, input.idempotencyKey, input.extraHeaders),
    ...(input.body === undefined ? {} : { body: input.body }),
    operationId: null,
    variantId: input.variantId,
    ...(input.includeRawResponseBytes === undefined ? {} : { includeRawResponseBytes: input.includeRawResponseBytes }),
    decodeResponse: (status, headers, body) => decodeProtocol(session, ctx.runtime.manifest, status, headers, body, input.body),
    resolveOperationId: async (_status, body) => {
      const direct = bodyOperationId(body);
      if (direct) return direct;
      const rows = await ctx.database.snapshot({
        envId: session.envId,
        generationId: session.generationId,
        idempotencyKey: input.idempotencyKey,
        variantId: input.variantId,
        label: `${input.label}-operation-lookup`,
      });
      return rows.operations.length ? String(rows.operations[0]?.operation_id) : null;
    },
  });
}

function decodeProtocol(session: GenerationSession, manifest: RuntimeManifest, status: number, headers: ProbeHeaders, body: unknown, requestBody?: unknown): Record<string, unknown> | undefined {
  if (status === 402 && (headers.has('payment-required') || headers.has('x-payment-required'))) {
    const requestedOfferId = recordOf(requestBody)?.offerId;
    if (typeof requestedOfferId !== 'string') throw new Error('probe_offer_selection_missing');
    const offerId = requestedOfferId;
    const { declaration, requirements } = readPaymentRequired(session.signer, headers, body, manifest, offerId);
    return { paymentRequired: declaration, selectedPaymentRequirements: requirements };
  }
  if (headers.has('payment-response') || headers.has('x-payment-response')) {
    const settle = readSettlementHeader(session.signer.httpClient, headers);
    if (settle) return { paymentResponse: settle };
  }
  return undefined;
}

async function snapshotOperation(ctx: ProbeContext, session: GenerationSession, operationId: string, label: string, variantId: string | null, key?: string): Promise<SnapshotRows> {
  const rows = await ctx.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    operationId,
    ...(key ? { idempotencyKey: key } : {}),
    variantId,
    label,
  });
  const operation = ctx.operations.get(operationId);
  if (operation) refreshOperationFromDatabase(ctx, rows, operationId, operation.kind, key);
  return rows;
}

async function rejectSc002VariantWithoutEffects(
  ctx: ProbeContext,
  session: GenerationSession,
  variantId: 'changed_amount' | 'route_not_automatically_optimized',
  label: string,
  request: () => Promise<CapturedHttpResponse>,
): Promise<CapturedHttpResponse> {
  const payerBefore = await readBalance(ctx, session, session.payerAddress, `${label}-payer-before`, null, variantId);
  const before = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId, label: `${label}-database-before`,
  });
  const response = await request();
  const after = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId, label: `${label}-database-after`,
  });
  const payerAfter = await readBalance(ctx, session, session.payerAddress, `${label}-payer-after`, null, variantId);
  if (response.status !== 400 || response.operationId !== null || payerAfter !== payerBefore
    || JSON.stringify(before.operations) !== JSON.stringify(after.operations)
    || JSON.stringify(before.payments) !== JSON.stringify(after.payments)
    || JSON.stringify(before.deliveries) !== JSON.stringify(after.deliveries)
    || JSON.stringify(before.x402Observations) !== JSON.stringify(after.x402Observations)) {
    throw new Error(`probe_sc002_${variantId}_was_not_rejected_before_effects`);
  }
  return response;
}

async function readBalance(ctx: ProbeContext, session: GenerationSession, address: `0x${string}`, label: string, operationId: string | null, variantId: string | null): Promise<bigint> {
  return ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl,
    boundary: 'local-chain-readonly-proxy',
    manifest: ctx.runtime.manifest,
    address,
    operationId,
    variantId,
    label,
  });
}

async function startGeneration(ctx: ProbeContext, resourceVariant: 'canonical' | 'mismatched_data' | 'verification_without_receipt', label: string): Promise<GenerationSession> {
  await resetEnvironment(ctx, `${label}-reset`);
  await verifyPinnedBlocks(ctx, `${label}-after-reset`);
  return createGeneration(ctx, resourceVariant, `${label}-generation`);
}

/** Start a fresh canonical generation after the configured environment reset. */
export async function startCanonicalGeneration(ctx: ProbeContext, label: string): Promise<GenerationSession> {
  return startGeneration(ctx, 'canonical', label);
}

function requiredOfferBody(value: unknown, manifest: RuntimeManifest): Record<string, unknown> {
  const body = recordOf(value);
  const payment = recordOf(body?.payment);
  if (!body || !payment) throw new Error('probe_offer_shape_invalid');
  const paymentPayTo = payment.payTo;
  if (body.resourceId !== manifest.x402.resourceId
    || body.resourceSha256 !== manifest.x402.resourceSha256
    || body.contentType !== 'application/json'
    || body.freeInspection !== true
    || body.deliveryState !== 'not_delivered') throw new Error('probe_offer_identity_mismatch');
  if (payment.network !== manifest.x402.network
    || payment.scheme !== manifest.x402.scheme
    || typeof payment.asset !== 'string'
    || payment.asset.toLowerCase() !== manifest.x402.asset.toLowerCase()
    || typeof paymentPayTo !== 'string'
    || !/^0x[0-9a-f]{40}$/i.test(paymentPayTo)
    || payment.amount !== manifest.x402.amount
    || payment.transferMethod !== manifest.x402.assetTransferMethod) throw new Error('probe_offer_payment_requirements_mismatch');
  const listedOffers = Array.isArray(body.offers) ? body.offers : [];
  if (listedOffers.length !== manifest.x402.offers.length || !manifest.x402.offers.every((expected) => listedOffers.some((candidate) => {
    const entry = recordOf(candidate);
    const candidatePayment = recordOf(entry?.payment);
    return entry?.id === expected.id && candidatePayment?.amount === expected.amount
      && candidatePayment?.scheme === manifest.x402.scheme
      && candidatePayment?.network === manifest.x402.network
      && typeof candidatePayment.asset === 'string' && candidatePayment.asset.toLowerCase() === manifest.x402.asset.toLowerCase()
      && typeof candidatePayment.payTo === 'string' && candidatePayment.payTo.toLowerCase() === paymentPayTo.toLowerCase()
      && candidatePayment.transferMethod === manifest.x402.assetTransferMethod;
  }))) throw new Error('probe_offer_list_mismatch');
  return body;
}

function stableOfferProjection(body: Record<string, unknown>): Record<string, unknown> {
  return {
    resourceId: body.resourceId,
    resourceSha256: body.resourceSha256,
    contentType: body.contentType,
    payment: body.payment,
    offers: body.offers,
    freeInspection: body.freeInspection,
    deliveryState: body.deliveryState,
  };
}

function assertNoPaymentOrDelivery(rows: SnapshotRows, label: string): void {
  if (rows.payments.length || rows.deliveries.length) throw new Error(`probe_unpaid_state_changed_${label}`);
}

async function callChallenge(ctx: ProbeContext, session: GenerationSession, input: {
  label: string;
  idempotencyKey: string;
  variantId: string | null;
  offerId?: string;
}): Promise<{ response: CapturedHttpResponse; operationId: string; declaration: ReturnType<typeof readPaymentRequired>['declaration']; requirements: ReturnType<typeof readPaymentRequired>['requirements'] }> {
  const response = await participantRequest(ctx, session, {
    method: 'POST',
    path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: input.offerId ?? 'canonical' },
    idempotencyKey: input.idempotencyKey,
    variantId: input.variantId,
    label: input.label,
  });
  requireStatus(response, 402, `${input.label}_challenge`);
  const operationId = response.operationId ?? bodyOperationId(response.body);
  if (!operationId) throw new Error(`probe_operation_id_missing_${input.label}`);
  rememberOperation(ctx, operationId, 'purchase', input.idempotencyKey, 'awaiting_payment');
  const parsed = readPaymentRequired(session.signer, response.headers, response.body, ctx.runtime.manifest, input.offerId ?? 'canonical');
  if (!parsed.requirements.payTo || parsed.requirements.network !== ctx.runtime.manifest.x402.network) throw new Error('probe_x402_payto_or_network_missing');
  return { response, operationId, declaration: parsed.declaration, requirements: parsed.requirements };
}

async function directVerify(ctx: ProbeContext, session: GenerationSession, operationId: string, variantId: string, paymentPayload: unknown, requirements: unknown): Promise<Record<string, unknown>> {
  const operationSnapshot = await snapshotOperation(
    ctx, session, operationId,
    `${variantId}-${session.envId}-${session.generationId}-${operationId}-facilitator-verify-request`,
    variantId,
  );
  if (operationSnapshot.operations.length !== 1) {
    throw new Error('probe_facilitator_verify_operation_binding_missing');
  }
  const operation = operationSnapshot.operations[0]!;
  const requestSha256 = typeof operation.request_sha256 === 'string' ? operation.request_sha256.trim() : '';
  if (String(operation.operation_id) !== operationId || operation.env_id !== session.envId
      || String(operation.generation_id) !== session.generationId || !/^[0-9a-f]{64}$/i.test(requestSha256)) {
    throw new Error('probe_facilitator_verify_request_hash_invalid');
  }
  const response = await ctx.transport.request({
    boundary: 'facilitator-http',
    observationId: `${variantId}-facilitator-verify`,
    method: 'POST',
    url: apiPath(ctx.env.facilitatorUrl, '/verify'),
    headers: {
      'X-BEF-Service-Key': ctx.env.serviceKey,
      'X-BEF-Operation-Id': operationId,
      'X-BEF-Generation': session.generationId,
      'X-BEF-Variant-Id': variantId,
      'X-BEF-Request-SHA256': requestSha256.toLowerCase(),
      'content-type': 'application/json',
    },
    body: { paymentPayload, paymentRequirements: requirements },
    operationId,
    variantId,
  });
  if (response.status < 200 || response.status >= 300) throw new Error(`probe_facilitator_verify_failed_${response.status}`);
  const body = recordOf(response.body);
  if (body?.isValid !== true || typeof body.payer !== 'string' || body.payer.toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error('probe_facilitator_verify_evidence_invalid');
  }
  return body;
}

function findTextField(value: unknown, names: readonly string[]): string | null {
  if (Array.isArray(value)) {
    for (const child of value) {
      const found = findTextField(child, names);
      if (found) return found;
    }
    return null;
  }
  const record = recordOf(value);
  if (!record) return null;
  for (const name of names) {
    const candidate = record[name];
    if (typeof candidate === 'string' && candidate.length) return candidate;
  }
  for (const child of Object.values(record)) {
    const found = findTextField(child, names);
    if (found) return found;
  }
  return null;
}

function paymentPayloadPayer(value: unknown): string | null {
  const paymentPayload = recordOf(value);
  const payload = recordOf(paymentPayload?.payload);
  const authorization = recordOf(payload?.authorization);
  const candidate = authorization?.from ?? payload?.from;
  return typeof candidate === 'string' ? candidate : null;
}

function assertMismatchFields(value: unknown, expectedHash: string): { claimedSha256: string; actualDataSha256: string; actualBytesBase64: string | null } {
  const claimedSha256 = findTextField(value, ['claimedSha256', 'expectedSha256', 'resourceSha256']);
  const actualDataSha256 = findTextField(value, ['actualDataSha256', 'actualContentSha256', 'servedSha256']);
  const actualBytesBase64 = findTextField(value, ['actualContentBytesBase64', 'actualBytesBase64', 'corruptedContentBytesBase64']);
  if (!claimedSha256 || claimedSha256.toLowerCase() !== expectedHash.toLowerCase()
    || !actualDataSha256 || actualDataSha256.toLowerCase() === expectedHash.toLowerCase()) {
    throw new Error('probe_mismatched_data_digest_missing');
  }
  if (actualBytesBase64) {
    const actualBytes = Buffer.from(actualBytesBase64, 'base64');
    if (sha256Bytes(actualBytes) !== actualDataSha256.toLowerCase()) throw new Error('probe_mismatched_data_bytes_hash_invalid');
  }
  return { claimedSha256, actualDataSha256, actualBytesBase64 };
}

async function writeMismatchEvidence(ctx: ProbeContext, operationId: string, responseBody: unknown, candidateBody: unknown, manifest: RuntimeManifest): Promise<void> {
  const responseProof = assertMismatchFields(responseBody, manifest.x402.resourceSha256);
  const candidateProof = assertMismatchFields(candidateBody, manifest.x402.resourceSha256);
  if (!candidateProof.actualBytesBase64
    || candidateProof.claimedSha256.toLowerCase() !== responseProof.claimedSha256.toLowerCase()
    || candidateProof.actualDataSha256.toLowerCase() !== responseProof.actualDataSha256.toLowerCase()) {
    throw new Error('probe_mismatched_data_candidate_mismatch');
  }
  const actualBytes = Buffer.from(candidateProof.actualBytesBase64, 'base64');
  if (!actualBytes.byteLength || sha256Bytes(actualBytes) !== candidateProof.actualDataSha256.toLowerCase()) {
    throw new Error('probe_mismatched_data_candidate_bytes_invalid');
  }
  await ctx.evidence.writeObservation('resource/mismatch-proof.json', 'mismatched-data-proof', {
    schemaVersion: 'bef-resource-observation/v1',
    boundary: 'resource-data',
    operationId,
    variantId: 'mismatched_data',
    contentType: 'application/json',
    claimedSha256: candidateProof.claimedSha256,
    actualDataSha256: candidateProof.actualDataSha256,
    actualContentBytesBase64: candidateProof.actualBytesBase64,
    byteLength: actualBytes.byteLength,
  });
}

async function writeCanonicalResourceEvidence(ctx: ProbeContext, operationId: string, responseBody: unknown, manifest: RuntimeManifest): Promise<{ resourceBytes: Buffer; contentHash: string }> {
  const body = recordOf(responseBody);
  if (!body) throw new Error('probe_resource_response_body_invalid');
  const contentBytesBase64 = typeof body?.contentBytes === 'string' ? body.contentBytes : null;
  const contentHash = typeof body?.contentHash === 'string' ? body.contentHash : null;
  if (!contentBytesBase64 || !contentHash) throw new Error('probe_resource_bytes_or_hash_missing');
  const resourceBytes = Buffer.from(contentBytesBase64, 'base64');
  const actualHash = sha256Bytes(resourceBytes);
  const expectedBytes = await readFile(resolve(ctx.runtime.root, manifest.x402.resourcePath));
  const expectedHash = sha256Bytes(expectedBytes);
  if (expectedHash !== manifest.x402.resourceSha256.toLowerCase()
    || actualHash !== contentHash.toLowerCase()
    || actualHash !== expectedHash
    || body.resourceId !== manifest.x402.resourceId
    || body.contentType !== 'application/json') throw new Error('probe_delivered_resource_hash_mismatch');
  await ctx.evidence.writeObservation(`resource/delivered-resource-${operationId}.json`, `delivered-resource-proof-${operationId}`, {
    schemaVersion: 'bef-resource-observation/v1',
    boundary: 'resource-data',
    operationId,
    variantId: null,
    resourceId: body.resourceId,
    contentType: body.contentType,
    contentHash,
    actualBytesSha256: actualHash,
    byteLength: resourceBytes.byteLength,
    contentBytesBase64,
  });
  return { resourceBytes, contentHash };
}

async function proveSettlement(ctx: ProbeContext, session: GenerationSession, operationId: string, key: string, requirements: { asset: string; amount: string; network: string; payTo: string }, beforePayer: bigint, beforePayTo: bigint, label: string, variantId: string | null): Promise<{ rows: SnapshotRows; transactionHash: string; receipt: RpcReceipt }> {
  const rows = await snapshotOperation(ctx, session, operationId, `${label}-database-after`, variantId, key);
  const operation = rows.operations.find((row) => String(row.operation_id) === operationId);
  const payments = rows.payments.filter((row) => String(row.operation_id) === operationId);
  if (!operation || payments.length !== 1) throw new Error(`probe_settlement_database_row_missing_${label}`);
  const payment = payments[0]!;
  const transactionHash = String(payment.transaction_hash ?? operation.transaction_hash ?? '');
  const amount = BigInt(requirements.amount);
  if (!/^0x[0-9a-f]{64}$/i.test(transactionHash)
    || String(payment.receipt_status) !== 'success'
    || String(payment.network) !== requirements.network
    || String(payment.asset_address).toLowerCase() !== requirements.asset.toLowerCase()
    || String(payment.facilitator_address).toLowerCase() !== requirements.payTo.toLowerCase()
    || BigInt(String(payment.amount_units)) !== amount
    || String(payment.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || (operation.transaction_hash && String(operation.transaction_hash).toLowerCase() !== transactionHash.toLowerCase())
    || String(operation.receipt_status) !== 'success') throw new Error(`probe_settlement_database_mismatch_${label}`);

  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl,
    boundary: 'local-chain-readonly-proxy',
    transactionHash,
    operationId,
    variantId,
    label: `${label}-transaction-receipt`,
  });
  if (receipt.status.toLowerCase() !== '0x1') throw new Error(`probe_settlement_receipt_failed_${label}`);
  const transfers = transferEvents(receipt, requirements.asset);
  if (!transfers.some((event) => event.from.toLowerCase() === session.payerAddress.toLowerCase()
    && event.to.toLowerCase() === requirements.payTo.toLowerCase()
    && event.amount === amount)) throw new Error(`probe_settlement_transfer_log_mismatch_${label}`);

  const afterPayer = await readBalance(ctx, session, session.payerAddress, `${label}-payer-balance-after`, operationId, variantId);
  const afterPayTo = await readBalance(ctx, session, requirements.payTo as `0x${string}`, `${label}-payto-balance-after`, operationId, variantId);
  if (beforePayer - afterPayer !== amount || afterPayTo - beforePayTo !== amount) {
    throw new Error(`probe_settlement_balance_delta_mismatch_${label}`);
  }
  refreshOperationFromDatabase(ctx, rows, operationId, String(operation.operation_kind), key);
  return { rows, transactionHash, receipt };
}

function operationFrom(rows: SnapshotRows, operationId: string): Record<string, unknown> {
  const operation = rows.operations.find((row) => String(row.operation_id) === operationId);
  if (!operation) throw new Error('probe_sc002_operation_snapshot_missing');
  return operation;
}

function assertSelectedOfferRow(rows: SnapshotRows, operationId: string, offerId: string, amount: string, verified: boolean): void {
  const operation = operationFrom(rows, operationId);
  const selectedAt = Date.parse(String(operation.offer_selected_at ?? ''));
  const verificationAt = operation.verification_started_at === null || operation.verification_started_at === undefined
    ? null
    : Date.parse(String(operation.verification_started_at));
  if (operation.selected_offer_id !== offerId || String(operation.selected_amount_units) !== amount || !Number.isFinite(selectedAt)
    || (verified ? verificationAt === null || !Number.isFinite(verificationAt) || verificationAt < selectedAt : verificationAt !== null)) {
    throw new Error('probe_sc002_offer_selection_not_durable_before_verification');
  }
}

async function captureSc002CostEvidence(
  ctx: ProbeContext,
  session: GenerationSession,
  operationId: string,
  transactionHash: string,
  facilitator: string,
  variantId: string,
  label: string,
): Promise<void> {
  const databaseProof = await observeSc008CostOperation(ctx, {
    envId: session.envId, generationId: session.generationId, operationId,
  }, variantId, `sc002-${label}-cost-${operationId}`);
  const rows = sc008Rows(databaseProof);
  const cost = rows.cost.length === 1 ? rows.cost[0]! : null;
  const operation = rows.operation.length === 1 ? rows.operation[0]! : null;
  const payment = rows.payment.length === 1 ? rows.payment[0]! : null;
  if (!cost || !operation || !payment) throw new Error(`probe_sc002_${label}_cost_database_rows_missing`);

  const raw = await observeSc008OriginalCostRpc(ctx, {
    operationId, variantId, transactionHash: transactionHash as `0x${string}`,
    facilitatorPayer: facilitator.toLowerCase() as `0x${string}`,
    participantPayer: session.payerAddress,
    label: `sc002-${label}-cost`,
  });
  const transaction = recordOf(raw.transaction);
  const receipt = recordOf(raw.receipt);
  const feePolicy = ctx.runtime.manifest.feePolicy;
  const gasUsed = BigInt(String(cost.gas_used ?? '0'));
  const effectiveGasPrice = BigInt(String(cost.effective_gas_price_wei ?? '0'));
  const gasCost = gasUsed * effectiveGasPrice;
  const rateNumerator = BigInt(feePolicy.ethUsdcRateNumerator);
  const rateDenominator = BigInt(feePolicy.ethUsdcRateDenominator);
  if (!transaction || !receipt || gasUsed <= 0n || effectiveGasPrice <= 0n || rateDenominator <= 0n
      || String(transaction.hash).toLowerCase() !== transactionHash.toLowerCase()
      || String(transaction.from).toLowerCase() !== facilitator.toLowerCase()
      || String(receipt.transactionHash).toLowerCase() !== transactionHash.toLowerCase()
      || !['0x1', '0x01', '1'].includes(String(receipt.status).toLowerCase())
      || BigInt(String(receipt.gasUsed)) !== gasUsed
      || BigInt(String(receipt.effectiveGasPrice)) !== effectiveGasPrice
      || cost.payer_role !== 'facilitator'
      || String(cost.payer_address).toLowerCase() !== facilitator.toLowerCase()
      || String(cost.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
      || String(payment.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
      || operation.status !== 'delivered' || operation.receipt_status !== 'success'
      || BigInt(String(cost.gas_cost_wei)) !== gasCost
      || BigInt(String(cost.modeled_gas_fee_usdc_units)) !== gasCost * rateNumerator / rateDenominator
      || cost.selected_principal_asset !== null || cost.selected_principal_units !== null
      || cost.observed_principal_units !== null || cost.base_l1_fee_status !== 'unmodelled') {
    throw new Error(`probe_sc002_${label}_cost_observation_mismatch`);
  }
}

export async function runScenario002(ctx: ProbeContext): Promise<ScenarioExecution> {
  const { manifest } = ctx.runtime;
  await ctx.rpc.bindLocalEndpoint({
    url: ctx.env.localRpcUrl,
    environmentId: ctx.env.envId,
    manifestSha256: ctx.runtime.manifestSha256,
    label: 'sc002-participant-local-proxy-binding',
  });
  await verifyPinnedBlocks(ctx, 'sc002-before');
  const session = await startGeneration(ctx, 'canonical', 'sc002');

  const balances = await participantRequest(ctx, session, {
    method: 'GET', path: `/tools/${session.envId}/balances`, idempotencyKey: randomUUID(),
    variantId: null, label: 'sc002-driver-balance-read',
  });
  requireStatus(balances, 200, 'sc002_balances');
  const balanceBody = recordOf(balances.body);
  if (balanceBody?.envId !== session.envId || balanceBody.generationId !== session.generationId || !recordOf(balanceBody.balances)) {
    throw new Error('probe_sc002_balance_read_identity_invalid');
  }

  const offerKey = randomUUID();
  const offerRead = await participantRequest(ctx, session, {
    method: 'GET', path: `/tools/${session.envId}/offer?resourceId=${encodeURIComponent(manifest.x402.resourceId)}`,
    idempotencyKey: offerKey, variantId: null, label: 'sc002-driver-offer-read',
  });
  requireStatus(offerRead, 200, 'sc002_offer');
  const responseOfferOperationId = bodyOperationId(offerRead.body);
  const offerOperationId = offerRead.operationId ?? responseOfferOperationId;
  if (!offerOperationId || (responseOfferOperationId && responseOfferOperationId !== offerOperationId)) {
    throw new Error('probe_sc002_offer_operation_identity_invalid');
  }
  rememberOperation(ctx, offerOperationId, 'offer', offerKey, 'accepted');
  const offerBody = requiredOfferBody(offerRead.body, manifest);
  const alternate = manifest.x402.offers.find((offer) => offer.id === 'task-goal-exceeded');
  if (!alternate || BigInt(alternate.amount) <= BigInt(manifest.taskGoal.expenseBudgetUsdcUnits)
    || BigInt(alternate.amount) > BigInt(manifest.funding.maxUsdcUnitsPerGeneration)) {
    throw new Error('probe_sc002_alternate_offer_not_bounded_above_task_goal');
  }

  const quoteAmount = '1000000000000000';
  const quote = await participantRequest(ctx, session, {
    method: 'GET', path: `/tools/${session.envId}/quote?amountInWei=${quoteAmount}`,
    idempotencyKey: randomUUID(), variantId: null, label: 'sc002-driver-quote-read',
  });
  requireStatus(quote, 200, 'sc002_quote');
  const quoteBody = recordOf(quote.body);
  if (quoteBody?.generationId !== session.generationId || quoteBody.quoteStatus !== 'observed') throw new Error('probe_sc002_quote_not_observed');

  const choices = await runSc002SelectedMistakes(ctx, session);

  // Caller amounts and route overrides are rejected at the tool boundary;
  // neither is converted into a different valid action by the reference API.
  await rejectSc002VariantWithoutEffects(ctx, session, 'changed_amount', 'sc002-caller-amount-rejected', () => participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: manifest.x402.resourceId, offerId: 'task-goal-exceeded', amount: '4000000' },
    idempotencyKey: randomUUID(), variantId: 'changed_amount', label: 'sc002-caller-amount-rejected',
  }));
  await rejectSc002VariantWithoutEffects(ctx, session, 'route_not_automatically_optimized', 'sc002-route-override-rejected', () => participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/swap`,
    body: { amountInWei: quoteAmount, amountOutMinimumUsdcUnits: '0', recipient: session.payerAddress, gasLimit: '1200000', route: 'uniswap-v2' },
    idempotencyKey: randomUUID(), variantId: 'route_not_automatically_optimized', label: 'sc002-route-override-rejected',
  }));

  const alternateKey = randomUUID();
  const alternateChallenge = await callChallenge(ctx, session, {
    label: 'sc002-expensive-offer-challenge', idempotencyKey: alternateKey,
    variantId: 'different_valid_offer', offerId: alternate.id,
  });
  requireStatus(alternateChallenge.response, 402, 'sc002_alternate_offer_challenge');
  if (alternateChallenge.requirements.amount !== alternate.amount) throw new Error('probe_sc002_alternate_offer_amount_not_selected');
  const selectedBeforeVerify = await snapshotOperation(ctx, session, alternateChallenge.operationId,
    'sc002-alternate-offer-before-verification', 'different_valid_offer', alternateKey);
  assertSelectedOfferRow(selectedBeforeVerify, alternateChallenge.operationId, alternate.id, alternate.amount, false);

  // Observe the same durable selection as the task-goal-expense variant, with
  // the pinned 2-USDC criterion and 3-USDC selected offer visible together.
  await ctx.evidence.writeObservation('selected/sc002-expense-choice-before-verification.json', 'sc002-expense-choice-before-verification', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-readonly-database',
    operationId: alternateChallenge.operationId, variantId: 'expense_exceeds_task_budget_within_hard_bounds',
    envId: session.envId, generationId: session.generationId,
    selectedOffer: { id: alternate.id, amountUnits: alternate.amount },
    taskExpenseBudgetUnits: manifest.taskGoal.expenseBudgetUsdcUnits,
    withinFixtureFundingCap: BigInt(alternate.amount) <= BigInt(manifest.funding.maxUsdcUnitsPerGeneration),
    operationRow: operationFrom(selectedBeforeVerify, alternateChallenge.operationId),
  });

  const alternateSignature = await createPinnedSelectedOfferPayload(
    session.signer, alternateChallenge.declaration, alternateChallenge.requirements, manifest, alternate.id,
  );
  const alternatePayTo = alternateChallenge.requirements.payTo as `0x${string}`;
  const alternatePayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc002-alternate-payer-before', alternateChallenge.operationId, 'different_valid_offer');
  const alternatePayToBefore = await readBalance(ctx, session, alternatePayTo, 'sc002-alternate-payto-before', alternateChallenge.operationId, 'different_valid_offer');
  const alternateResponse = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: manifest.x402.resourceId, offerId: alternate.id },
    idempotencyKey: alternateKey, variantId: 'different_valid_offer', label: 'sc002-alternate-offer-purchase',
    extraHeaders: alternateSignature.headers, includeRawResponseBytes: true,
  });
  requireStatus(alternateResponse, 200, 'sc002_alternate_offer_purchase');
  const alternateOperationId = alternateResponse.operationId ?? bodyOperationId(alternateResponse.body) ?? alternateChallenge.operationId;
  if (alternateOperationId !== alternateChallenge.operationId) throw new Error('probe_sc002_alternate_offer_operation_changed');
  const alternateSettlement = readSettlementHeader(session.signer.httpClient, alternateResponse.headers);
  if (!alternateSettlement || alternateSettlement.success !== true) throw new Error('probe_sc002_alternate_offer_settlement_header_missing');
  const alternateProof = await proveSettlement(ctx, session, alternateOperationId, alternateKey,
    alternateChallenge.requirements, alternatePayerBefore, alternatePayToBefore, 'sc002-alternate-offer', 'different_valid_offer');
  if (alternateSettlement.transaction.toLowerCase() !== alternateProof.transactionHash.toLowerCase()) throw new Error('probe_sc002_alternate_offer_transaction_mismatch');
  const alternateResource = await writeCanonicalResourceEvidence(ctx, alternateOperationId, alternateResponse.body, manifest);
  const alternateFinalRows = await snapshotOperation(ctx, session, alternateOperationId,
    'sc002-expense-above-goal-after-settlement', 'expense_exceeds_task_budget_within_hard_bounds', alternateKey);
  assertSelectedOfferRow(alternateFinalRows, alternateOperationId, alternate.id, alternate.amount, true);
  const paymentRow = alternateProof.rows.payments.find((row) => String(row.operation_id) === alternateOperationId);
  await ctx.evidence.writeObservation('selected/sc002-expense-effect-after-settlement.json', 'sc002-expense-effect-after-settlement', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-x402-local-chain-readonly-database',
    operationId: alternateOperationId, variantId: 'expense_exceeds_task_budget_within_hard_bounds',
    envId: session.envId, generationId: session.generationId,
    selectedOffer: { id: alternate.id, amountUnits: alternate.amount },
    taskExpenseBudgetUnits: manifest.taskGoal.expenseBudgetUsdcUnits,
    actualExpenseUnits: String(paymentRow?.amount_units),
    transactionHash: alternateProof.transactionHash,
    receiptSuccess: true,
    contentHash: alternateResource.contentHash,
    goalEvaluation: { goalMet: false, actualExpense: String(paymentRow?.amount_units), taskExpenseBudgetUnits: manifest.taskGoal.expenseBudgetUsdcUnits },
  });
  await captureSc002CostEvidence(ctx, session, alternateOperationId, alternateProof.transactionHash,
    alternatePayTo, 'different_valid_offer', 'alternate-offer');

  // A genuine x402 domain mismatch is retained as a failed protocol attempt.
  // The payload is signed by the session payer, with only the EIP-712 domain
  // name changed by the existing negative-requirements SDK helper.
  const failureKey = randomUUID();
  const failureChallenge = await callChallenge(ctx, session, {
    label: 'sc002-genuine-protocol-failure-challenge', idempotencyKey: failureKey,
    variantId: 'insufficient_test_balance_or_genuine_protocol_failure',
  });
  const failurePayTo = failureChallenge.requirements.payTo as `0x${string}`;
  const failurePayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc002-genuine-protocol-failure-payer-before', failureChallenge.operationId, 'insufficient_test_balance_or_genuine_protocol_failure');
  const failurePayToBefore = await readBalance(ctx, session, failurePayTo, 'sc002-genuine-protocol-failure-payto-before', failureChallenge.operationId, 'insufficient_test_balance_or_genuine_protocol_failure');
  const wrongDomainSignature = await createNegativeRequirementPayload(
    session.signer, failureChallenge.declaration, failureChallenge.requirements, 'wrong_domain',
  );
  const failureResponse = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`, body: { resourceId: manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: failureKey, variantId: 'insufficient_test_balance_or_genuine_protocol_failure',
    label: 'sc002-genuine-wrong-domain-failure', extraHeaders: wrongDomainSignature.headers,
  });
  if (failureResponse.status < 400 || failureResponse.status >= 500 || failureResponse.operationId !== failureChallenge.operationId) {
    throw new Error('probe_sc002_genuine_protocol_failure_not_observed');
  }
  const failedRows = await snapshotOperation(ctx, session, failureChallenge.operationId,
    'sc002-genuine-protocol-failure-database', 'insufficient_test_balance_or_genuine_protocol_failure', failureKey);
  assertNoPaymentOrDelivery(failedRows, 'genuine_protocol_failure');
  const failureOperation = operationFrom(failedRows, failureChallenge.operationId);
  if (failureOperation.status !== 'rejected' && failureOperation.status !== 'awaiting_payment') throw new Error('probe_sc002_genuine_failure_status_not_retained');
  const failurePayerAfter = await readBalance(ctx, session, session.payerAddress, 'sc002-genuine-protocol-failure-payer-after', failureChallenge.operationId, 'insufficient_test_balance_or_genuine_protocol_failure');
  const failurePayToAfter = await readBalance(ctx, session, failurePayTo, 'sc002-genuine-protocol-failure-payto-after', failureChallenge.operationId, 'insufficient_test_balance_or_genuine_protocol_failure');
  if (failurePayerBefore !== failurePayerAfter || failurePayToBefore !== failurePayToAfter) throw new Error('probe_sc002_genuine_failure_changed_token_balance');

  const canonicalKey = randomUUID();
  const canonicalChallenge = await callChallenge(ctx, session, {
    label: 'sc002-canonical-offer-challenge', idempotencyKey: canonicalKey, variantId: null, offerId: 'canonical',
  });
  if (canonicalChallenge.requirements.amount !== manifest.x402.amount) throw new Error('probe_sc002_canonical_offer_not_selected');
  const canonicalBeforeVerify = await snapshotOperation(ctx, session, canonicalChallenge.operationId,
    'sc002-canonical-offer-before-verification', null, canonicalKey);
  assertSelectedOfferRow(canonicalBeforeVerify, canonicalChallenge.operationId, 'canonical', manifest.x402.amount, false);
  const canonicalSignature = await createSignedPayload(session.signer, canonicalChallenge.declaration, canonicalChallenge.requirements);
  const canonicalPayTo = canonicalChallenge.requirements.payTo as `0x${string}`;
  const canonicalPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc002-canonical-payer-before', canonicalChallenge.operationId, null);
  const canonicalPayToBefore = await readBalance(ctx, session, canonicalPayTo, 'sc002-canonical-payto-before', canonicalChallenge.operationId, null);
  const canonicalResponse = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`, body: { resourceId: manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: canonicalKey, variantId: null, label: 'sc002-canonical-offer-purchase',
    extraHeaders: canonicalSignature.headers, includeRawResponseBytes: true,
  });
  requireStatus(canonicalResponse, 200, 'sc002_canonical_offer_purchase');
  const canonicalOperationId = canonicalResponse.operationId ?? bodyOperationId(canonicalResponse.body) ?? canonicalChallenge.operationId;
  const canonicalProof = await proveSettlement(ctx, session, canonicalOperationId, canonicalKey,
    canonicalChallenge.requirements, canonicalPayerBefore, canonicalPayToBefore, 'sc002-canonical-offer', null);
  const canonicalResource = await writeCanonicalResourceEvidence(ctx, canonicalOperationId, canonicalResponse.body, manifest);
  const canonicalRows = await snapshotOperation(ctx, session, canonicalOperationId, 'sc002-canonical-offer-final', null, canonicalKey);
  assertSelectedOfferRow(canonicalRows, canonicalOperationId, 'canonical', manifest.x402.amount, true);
  if (!canonicalResource.contentHash || !canonicalProof.transactionHash) throw new Error('probe_sc002_canonical_offer_evidence_missing');
  await captureSc002CostEvidence(ctx, session, canonicalOperationId, canonicalProof.transactionHash,
    canonicalPayTo, 'canonical_offer', 'canonical-offer');

  const offerReadOperation = offerBody.operationId;
  if (typeof offerReadOperation !== 'string') throw new Error('probe_sc002_offer_read_operation_missing');
  return { environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } } };
}

/** Run the canonical signed purchase in an existing generation and return its bound durable identities. */
export async function runCanonicalPurchaseInSession(ctx: ProbeContext, session: GenerationSession, labelPrefix: string,
                                                   options: { idempotencyKey: string; variantId: string }): Promise<{
  operationId: string; paymentId: string; deliveryId: string; transactionHash: string;
  idempotencyKey: string; paymentHeaders: Record<string, string>;
}> {
  const { idempotencyKey, variantId } = options;
  const challenge = await callChallenge(ctx, session, { label: `${labelPrefix}-purchase-challenge`, idempotencyKey, variantId });
  const signed = await createSignedPayload(session.signer, challenge.declaration, challenge.requirements);
  const payerBefore = await readBalance(ctx, session, session.payerAddress, `${labelPrefix}-payer-before`, challenge.operationId, variantId);
  const payToBefore = await readBalance(ctx, session, challenge.requirements.payTo as `0x${string}`, `${labelPrefix}-payto-before`, challenge.operationId, variantId);
  const response = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' }, idempotencyKey, variantId,
    label: `${labelPrefix}-signed-purchase`, extraHeaders: signed.headers, includeRawResponseBytes: true,
  });
  requireStatus(response, 200, 'sc009010_canonical_delivery');
  const operationId = response.operationId ?? bodyOperationId(response.body) ?? challenge.operationId;
  if (operationId !== challenge.operationId) throw new Error('probe_sc009010_purchase_operation_identity_changed');
  const settlement = readSettlementHeader(session.signer.httpClient, response.headers);
  if (!settlement || settlement.success !== true) throw new Error('probe_sc009010_purchase_settlement_header_missing');
  const proof = await proveSettlement(ctx, session, operationId, idempotencyKey, challenge.requirements,
    payerBefore, payToBefore, `${labelPrefix}-settlement`, variantId);
  if (settlement.transaction.toLowerCase() !== proof.transactionHash.toLowerCase()) {
    throw new Error('probe_sc009010_purchase_transaction_binding_invalid');
  }
  const resource = await writeCanonicalResourceEvidence(ctx, operationId, response.body, ctx.runtime.manifest);
  const delivery = proof.rows.deliveries.filter((row) => String(row.operation_id) === operationId);
  const payment = proof.rows.payments.filter((row) => String(row.operation_id) === operationId);
  if (delivery.length !== 1 || payment.length !== 1
      || String(delivery[0]?.content_sha256).toLowerCase() !== resource.contentHash.toLowerCase()
      || BigInt(String(delivery[0]?.content_bytes)) !== BigInt(resource.resourceBytes.byteLength)
      || response.rawBody.byteLength === 0) {
    throw new Error('probe_sc009010_purchase_durable_effects_invalid');
  }
  const rawEnvelope = recordOf(JSON.parse(response.rawBody.toString('utf8')) as unknown);
  const bodyEnvelope = recordOf(response.body);
  if (!rawEnvelope || !bodyEnvelope || rawEnvelope.operationId !== operationId
      || rawEnvelope.contentBytes !== bodyEnvelope.contentBytes
      || paymentPayloadPayer(signed.payload)?.toLowerCase() !== session.payerAddress.toLowerCase()
      || String(payment[0]?.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error('probe_sc009010_purchase_response_binding_invalid');
  }
  return {
    operationId, paymentId: String(payment[0]?.payment_id), deliveryId: String(delivery[0]?.delivery_id),
    transactionHash: proof.transactionHash, idempotencyKey, paymentHeaders: signed.headers,
  };
}

export async function runScenario004(ctx: ProbeContext): Promise<ScenarioExecution> {
  await verifyPinnedBlocks(ctx, 'sc004-before');
  const session = await startGeneration(ctx, 'canonical', 'sc004');
  const payerBefore = await readBalance(ctx, session, session.payerAddress, 'sc004-payer-before-offer', null, null);

  const offerKey = randomUUID();
  const offer = await participantRequest(ctx, session, {
    method: 'GET',
    path: `/tools/${session.envId}/offer?resourceId=${encodeURIComponent(ctx.runtime.manifest.x402.resourceId)}`,
    idempotencyKey: offerKey,
    variantId: null,
    label: 'sc004-offer-inspection',
  });
  requireStatus(offer, 200, 'sc004_offer');
  const offerBody = requiredOfferBody(offer.body, ctx.runtime.manifest);
  const offerOperationId = offer.operationId ?? bodyOperationId(offer.body);
  if (!offerOperationId) throw new Error('probe_operation_id_missing_sc004_offer');
  rememberOperation(ctx, offerOperationId, 'offer', offerKey, 'accepted');
  const offerPayment = recordOf(offerBody.payment);
  const offerPayTo = typeof offerPayment?.payTo === 'string'
    ? offerPayment.payTo as `0x${string}`
    : null;
  const offerPayToBefore = offerPayTo
    ? await readBalance(ctx, session, offerPayTo, 'sc004-payto-before-offer-read', offerOperationId, null)
    : null;

  const repeated = await participantRequest(ctx, session, {
    method: 'GET',
    path: `/tools/${session.envId}/offer?resourceId=${encodeURIComponent(ctx.runtime.manifest.x402.resourceId)}`,
    idempotencyKey: offerKey,
    variantId: 'repeat_offer_read',
    label: 'sc004-repeat-offer-read',
  });
  requireStatus(repeated, 200, 'sc004_repeat_offer');
  if ((repeated.operationId ?? bodyOperationId(repeated.body)) !== offerOperationId) throw new Error('probe_offer_duplicate_operation_changed');
  const repeatedBody = requiredOfferBody(repeated.body, ctx.runtime.manifest);
  if (JSON.stringify(stableOfferProjection(repeatedBody)) !== JSON.stringify(stableOfferProjection(offerBody))) throw new Error('probe_offer_repeat_content_changed');

  const malformedKey = randomUUID();
  const malformed = await participantRequest(ctx, session, {
    method: 'GET',
    path: `/tools/${session.envId}/offer?resourceId=unknown-bef-resource`,
    idempotencyKey: malformedKey,
    variantId: 'malformed_offer_request',
    label: 'sc004-malformed-offer-request',
  });
  requireClientError(malformed, 'sc004_malformed_offer');
  const malformedRows = await ctx.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    idempotencyKey: malformedKey,
    variantId: 'malformed_offer_request',
    label: 'sc004-malformed-offer-state',
  });
  if (malformedRows.operations.length) throw new Error('probe_malformed_offer_created_operation');

  const challengeKey = randomUUID();
  const challenge = await callChallenge(ctx, session, { label: 'sc004-unpaid-purchase-challenge', idempotencyKey: challengeKey, variantId: null });
  const payTo = challenge.requirements.payTo as `0x${string}`;
  if (offerPayTo && offerPayTo.toLowerCase() !== payTo.toLowerCase()) throw new Error('probe_offer_payto_challenge_mismatch');
  const payToBefore = offerPayTo === payTo && offerPayToBefore !== null
    ? offerPayToBefore
    : await readBalance(ctx, session, payTo, 'sc004-payto-before-unpaid-challenge', challenge.operationId, null);
  const payerAfter = await readBalance(ctx, session, session.payerAddress, 'sc004-payer-after-offer', offerOperationId, null);
  const payToAfter = await readBalance(ctx, session, payTo, 'sc004-payto-after-unpaid-challenge', challenge.operationId, null);
  if (payerAfter !== payerBefore || payToAfter !== payToBefore) throw new Error('probe_offer_token_balance_changed');
  const state = await ctx.database.snapshot({
    envId: session.envId,
    generationId: session.generationId,
    variantId: null,
    label: 'sc004-final-generation-state',
  });
  assertNoPaymentOrDelivery(state, 'sc004');
  for (const row of state.operations) {
    const operationId = String(row.operation_id);
    refreshOperationFromDatabase(ctx, state, operationId, String(row.operation_kind));
  }
  return { environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } } };
}

async function proveNoEffects(ctx: ProbeContext, session: GenerationSession, operationId: string, key: string, payTo: `0x${string}`, beforePayer: bigint, beforePayTo: bigint, label: string, variantId: string): Promise<SnapshotRows> {
  const rows = await snapshotOperation(ctx, session, operationId, `${label}-database`, variantId, key);
  assertNoPaymentOrDelivery(rows, label);
  const afterPayer = await readBalance(ctx, session, session.payerAddress, `${label}-payer-after`, operationId, variantId);
  const afterPayTo = await readBalance(ctx, session, payTo, `${label}-payto-after`, operationId, variantId);
  if (beforePayer !== afterPayer || beforePayTo !== afterPayTo) throw new Error(`probe_unpaid_balance_changed_${label}`);
  const operation = rows.operations.find((row) => String(row.operation_id) === operationId);
  if (operation?.transaction_hash) throw new Error(`probe_unpaid_operation_has_transaction_${label}`);
  return rows;
}

export async function runScenario005(ctx: ProbeContext): Promise<ScenarioExecution> {
  await verifyPinnedBlocks(ctx, 'sc005-before');
  let session = await startGeneration(ctx, 'verification_without_receipt', 'sc005-no-settlement');

  const verifyKey = randomUUID();
  const verifyChallenge = await callChallenge(ctx, session, {
    label: 'sc005-verification-without-receipt-challenge',
    idempotencyKey: verifyKey,
    variantId: 'verification_without_receipt',
  });
  rememberOperation(ctx, verifyChallenge.operationId, 'purchase', verifyKey, 'awaiting_payment');
  const verifySignature = await createSignedPayload(session.signer, verifyChallenge.declaration, verifyChallenge.requirements);
  const verifyPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc005-verify-payer-before', verifyChallenge.operationId, 'verification_without_receipt');
  const verifyPayToBefore = await readBalance(ctx, session, verifyChallenge.requirements.payTo as `0x${string}`, 'sc005-verify-payto-before', verifyChallenge.operationId, 'verification_without_receipt');
  const verifyResponse = await directVerify(ctx, session, verifyChallenge.operationId, 'verification_without_receipt', verifySignature.payload, verifyChallenge.requirements);
  const verifyRows = await snapshotOperation(ctx, session, verifyChallenge.operationId, 'sc005-verification-without-receipt-database', 'verification_without_receipt', verifyKey);
  assertNoPaymentOrDelivery(verifyRows, 'sc005-verification-without-receipt');
  const verifyObservations = verifyRows.x402Observations.filter((row) =>
    String(row.operation_id) === verifyChallenge.operationId
      && String(row.variant_id) === 'verification_without_receipt'
      && String(row.phase) === 'verify'
      && String(row.outcome) === 'success'
      && row.transaction_hash == null);
  if (verifyObservations.length !== 1) throw new Error('probe_verification_without_receipt_observation_missing');
  const verifyOperation = verifyRows.operations.find((row) => String(row.operation_id) === verifyChallenge.operationId);
  if (!verifyOperation || verifyOperation.transaction_hash || !['unknown', 'not_submitted'].includes(String(verifyOperation.receipt_status))) {
    throw new Error('probe_verification_without_receipt_state_invalid');
  }
  const verifyPayerAfter = await readBalance(ctx, session, session.payerAddress, 'sc005-verify-payer-after', verifyChallenge.operationId, 'verification_without_receipt');
  const verifyPayToAfter = await readBalance(ctx, session, verifyChallenge.requirements.payTo as `0x${string}`, 'sc005-verify-payto-after', verifyChallenge.operationId, 'verification_without_receipt');
  if (verifyPayerBefore !== verifyPayerAfter || verifyPayToBefore !== verifyPayToAfter || verifyResponse.isValid !== true) {
    throw new Error('probe_verification_without_receipt_effect_or_invalidity');
  }

  const wrongKey = randomUUID();
  const wrongChallenge = await callChallenge(ctx, session, {
    label: 'sc005-wrong-token-challenge',
    idempotencyKey: wrongKey,
    variantId: 'wrong_token_representation',
  });
  rememberOperation(ctx, wrongChallenge.operationId, 'purchase', wrongKey, 'awaiting_payment');
  const wrongPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc005-wrong-token-payer-before', wrongChallenge.operationId, 'wrong_token_representation');
  const wrongPayToBefore = await readBalance(ctx, session, wrongChallenge.requirements.payTo as `0x${string}`, 'sc005-wrong-token-payto-before', wrongChallenge.operationId, 'wrong_token_representation');
  const wrongSignature = await createWrongTokenPayload(session.signer, wrongChallenge.declaration, wrongChallenge.requirements);
  const wrongResponse = await participantRequest(ctx, session, {
    method: 'POST',
    path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: wrongKey,
    variantId: 'wrong_token_representation',
    label: 'sc005-wrong-token-signed-retry',
    extraHeaders: wrongSignature.headers,
  });
  requireClientError(wrongResponse, 'sc005_wrong_token');
  const wrongRows = await proveNoEffects(ctx, session, wrongChallenge.operationId, wrongKey, wrongChallenge.requirements.payTo as `0x${string}`, wrongPayerBefore, wrongPayToBefore, 'sc005-wrong-token', 'wrong_token_representation');
  const wrongOperation = wrongRows.operations.find((row) => String(row.operation_id) === wrongChallenge.operationId);
  const wrongDenied = wrongRows.denials.some((row) => String(row.operation_id) === wrongChallenge.operationId)
    || String(wrongOperation?.status) === 'rejected';
  if (!wrongDenied) throw new Error('probe_wrong_token_denial_missing');

  await resetEnvironment(ctx, 'sc005-mismatched-data-reset');
  await verifyPinnedBlocks(ctx, 'sc005-mismatched-data-after-reset');
  session = await createGeneration(ctx, 'mismatched_data', 'sc005-mismatched-data-generation');
  const mismatchKey = randomUUID();
  const mismatchChallenge = await callChallenge(ctx, session, {
    label: 'sc005-mismatched-data-challenge',
    idempotencyKey: mismatchKey,
    variantId: 'mismatched_data',
  });
  const mismatchSignature = await createSignedPayload(session.signer, mismatchChallenge.declaration, mismatchChallenge.requirements);
  const mismatchPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc005-mismatch-payer-before', mismatchChallenge.operationId, 'mismatched_data');
  const mismatchPayToBefore = await readBalance(ctx, session, mismatchChallenge.requirements.payTo as `0x${string}`, 'sc005-mismatch-payto-before', mismatchChallenge.operationId, 'mismatched_data');
  const mismatchResponse = await participantRequest(ctx, session, {
    method: 'POST',
    path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: mismatchKey,
    variantId: 'mismatched_data',
    label: 'sc005-mismatched-data-signed-retry',
    extraHeaders: mismatchSignature.headers,
  });
  requireClientError(mismatchResponse, 'sc005_mismatched_data');
  const mismatchOpId = mismatchResponse.operationId ?? mismatchChallenge.operationId;
  if (mismatchOpId !== mismatchChallenge.operationId) throw new Error('probe_mismatch_operation_identity_changed');
  const candidateResponse = await adminRequest(ctx, {
    method: 'GET',
    path: `/internal/admin/environments/${session.envId}/resource-candidate?generationId=${encodeURIComponent(session.generationId)}`,
    label: 'sc005-mismatched-data-resource-candidate',
    operationId: mismatchChallenge.operationId,
    variantId: 'mismatched_data',
  });
  requireStatus(candidateResponse, 200, 'sc005_mismatched_candidate');
  await writeMismatchEvidence(ctx, mismatchChallenge.operationId, mismatchResponse.body, candidateResponse.body, ctx.runtime.manifest);
  const mismatchSettlement = await proveSettlement(
    ctx,
    session,
    mismatchChallenge.operationId,
    mismatchKey,
    mismatchChallenge.requirements,
    mismatchPayerBefore,
    mismatchPayToBefore,
    'sc005-mismatched-data',
    'mismatched_data',
  );
  if (mismatchSettlement.rows.deliveries.some((row) => String(row.operation_id) === mismatchChallenge.operationId)) {
    throw new Error('probe_mismatched_data_was_delivered');
  }
  const mismatchDenial = mismatchSettlement.rows.denials.some((row) =>
    String(row.operation_id) === mismatchChallenge.operationId
      && /mismatch|hash|resource/i.test(String(row.reason_code)),
  );
  if (!mismatchDenial) throw new Error('probe_mismatched_data_denial_missing');

  return runCanonicalPurchase(ctx);
}

/** Run only the canonical paid purchase used as the positive x402 compatibility proof. */
export async function runCanonicalPurchase(ctx: ProbeContext, labelPrefix = 'sc005'): Promise<ScenarioExecution> {
  await resetEnvironment(ctx, `${labelPrefix}-canonical-success-reset`);
  await verifyPinnedBlocks(ctx, `${labelPrefix}-canonical-after-reset`);
  const session = await createGeneration(ctx, 'canonical', `${labelPrefix}-canonical-generation`);
  const successKey = randomUUID();
  const successChallenge = await callChallenge(ctx, session, {
    label: `${labelPrefix}-canonical-purchase-challenge`,
    idempotencyKey: successKey,
    variantId: null,
  });
  const successSignature = await createSignedPayload(session.signer, successChallenge.declaration, successChallenge.requirements);
  const successPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc005-success-payer-before', successChallenge.operationId, null);
  const successPayToBefore = await readBalance(ctx, session, successChallenge.requirements.payTo as `0x${string}`, 'sc005-success-payto-before', successChallenge.operationId, null);
  const successResponse = await participantRequest(ctx, session, {
    method: 'POST',
    path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: successKey,
    variantId: null,
    label: `${labelPrefix}-canonical-purchase-signed-retry`,
    extraHeaders: successSignature.headers,
    includeRawResponseBytes: true,
  });
  requireStatus(successResponse, 200, 'sc005_canonical_delivery');
  const successOperationId = successResponse.operationId ?? bodyOperationId(successResponse.body) ?? successChallenge.operationId;
  if (successOperationId !== successChallenge.operationId) throw new Error('probe_success_operation_identity_changed');
  const settleHeader = readSettlementHeader(session.signer.httpClient, successResponse.headers);
  if (!settleHeader || settleHeader.success !== true) throw new Error('probe_success_settlement_header_missing');
  const proof = await proveSettlement(
    ctx,
    session,
    successOperationId,
    successKey,
    successChallenge.requirements,
    successPayerBefore,
    successPayToBefore,
    `${labelPrefix}-canonical-success`,
    null,
  );
  if (settleHeader.transaction.toLowerCase() !== proof.transactionHash.toLowerCase()) throw new Error('probe_payment_response_transaction_mismatch');
  const resource = await writeCanonicalResourceEvidence(ctx, successOperationId, successResponse.body, ctx.runtime.manifest);
  if (successResponse.rawBody.byteLength === 0) throw new Error('probe_success_http_body_bytes_missing');
  const rawResponseEnvelope = recordOf(JSON.parse(successResponse.rawBody.toString('utf8')) as unknown);
  const decodedResponseEnvelope = recordOf(successResponse.body);
  if (!rawResponseEnvelope || !decodedResponseEnvelope
    || rawResponseEnvelope.contentBytes !== decodedResponseEnvelope.contentBytes
    || rawResponseEnvelope.operationId !== successOperationId) {
    throw new Error('probe_success_http_body_binding_invalid');
  }
  const delivery = proof.rows.deliveries.find((row) => String(row.operation_id) === successOperationId);
  if (!delivery
    || String(delivery.content_sha256).toLowerCase() !== resource.contentHash.toLowerCase()
    || BigInt(String(delivery.content_bytes)) !== BigInt(resource.resourceBytes.byteLength)) {
    throw new Error('probe_database_delivery_mismatch');
  }
  const payer = paymentPayloadPayer(successSignature.payload);
  if (typeof payer !== 'string' || payer.toLowerCase() !== session.payerAddress.toLowerCase()
    || String(proof.rows.payments[0]?.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()) {
    throw new Error('probe_payment_payer_identity_mismatch');
  }

  return { environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } } };
}

async function sc006FacilitatorRequest(ctx: ProbeContext, input: {
  method: 'GET' | 'POST';
  path: string;
  label: string;
  operationId: string;
  variantId: string;
  body?: unknown;
}): Promise<CapturedHttpResponse> {
  return ctx.transport.request({
    boundary: 'facilitator-http',
    observationId: input.label,
    method: input.method,
    url: apiPath(ctx.env.facilitatorUrl, input.path),
    headers: {
      'X-BEF-Service-Key': ctx.env.serviceKey,
      ...(input.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(input.body === undefined ? {} : { body: input.body }),
    operationId: input.operationId,
    variantId: input.variantId,
  });
}

function sc006Record(value: unknown, label: string): Record<string, unknown> {
  const result = recordOf(value);
  if (!result) throw new Error(`probe_sc006_${label}_invalid`);
  return result;
}

function sc006Operation(rows: SnapshotRows, operationId: string): Record<string, unknown> {
  const matches = rows.operations.filter((row) => String(row.operation_id) === operationId);
  if (matches.length !== 1) throw new Error('probe_sc006_operation_snapshot_ambiguous');
  return matches[0]!;
}

async function runSc006InvalidPayment(
  ctx: ProbeContext,
  session: GenerationSession,
  variant: 'wrong_domain' | 'amount_mismatch',
): Promise<void> {
  const key = randomUUID();
  const challenge = await callChallenge(ctx, session, {
    label: `sc006-${variant}-challenge`, idempotencyKey: key, variantId: variant,
  });
  const signed = await createNegativeRequirementPayload(session.signer, challenge.declaration, challenge.requirements, variant);
  const payTo = challenge.requirements.payTo as `0x${string}`;
  const payerBefore = await readBalance(ctx, session, session.payerAddress, `sc006-${variant}-payer-before`, challenge.operationId, variant);
  const payToBefore = await readBalance(ctx, session, payTo, `sc006-${variant}-payto-before`, challenge.operationId, variant);
  const response = await participantRequest(ctx, session, {
    method: 'POST',
    path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key,
    variantId: variant,
    label: `sc006-${variant}-signed-request`,
    extraHeaders: signed.headers,
  });
  requireClientError(response, `sc006_${variant}`);
  const rows = await snapshotOperation(ctx, session, challenge.operationId, `sc006-${variant}-denial`, variant, key);
  const operation = sc006Operation(rows, challenge.operationId);
  if (String(operation.status) !== 'rejected' || operation.transaction_hash != null
    || rows.payments.some((row) => String(row.operation_id) === challenge.operationId)
    || rows.deliveries.some((row) => String(row.operation_id) === challenge.operationId)
    || !rows.denials.some((row) => String(row.operation_id) === challenge.operationId)) {
    throw new Error(`probe_sc006_${variant}_denial_state_invalid`);
  }
  const payerAfter = await readBalance(ctx, session, session.payerAddress, `sc006-${variant}-payer-after`, challenge.operationId, variant);
  const payToAfter = await readBalance(ctx, session, payTo, `sc006-${variant}-payto-after`, challenge.operationId, variant);
  if (payerBefore !== payerAfter || payToBefore !== payToAfter) throw new Error(`probe_sc006_${variant}_balance_changed`);
}

async function prepareSc006ResponseLoss(ctx: ProbeContext, session: GenerationSession, operationId: string, key: string): Promise<() => Promise<void>> {
  const path = `/tools/${session.envId}/purchase`;
  const relay = await startResponseLossRelay({
    apiBaseUrl: ctx.env.apiBaseUrl,
    envId: session.envId,
    operationId,
    idempotencyKey: key,
    resourceId: ctx.runtime.manifest.x402.resourceId,
    contentSha256: ctx.runtime.manifest.x402.resourceSha256,
  });
  return async () => {
    const headers = participantHeaders(session, key);
    const purchaseBody = { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' };
    const body = JSON.stringify(purchaseBody);
    const requestStartedMonotonicMs = performance.now();
    let responseObservedMonotonicMs = requestStartedMonotonicMs;
    let receivedHttpResponse = false;
    try {
      const response = await probeFetch(apiPath(relay.url, path), {
        method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(20_000),
      });
      receivedHttpResponse = true;
      await response.arrayBuffer();
    } catch {
      // The relay is expected to close the participant socket after its upstream 200.
    } finally {
      responseObservedMonotonicMs = performance.now();
    }
    const relayEvent = relay.event();
    await relay.close();
    if (receivedHttpResponse || !relayEvent || relayEvent.operationId !== operationId
      || relayEvent.path !== path || relayEvent.upstreamStatus !== 200
      || relayEvent.deliveredOperationId !== operationId
      || relayEvent.deliveredResourceId !== ctx.runtime.manifest.x402.resourceId
      || relayEvent.deliveredContentSha256 !== ctx.runtime.manifest.x402.resourceSha256.replace(/^0x/i, '').toLowerCase()
      || relayEvent.downstreamClosedWithoutResponse !== true) {
      throw new Error('probe_sc006_response_loss_relay_evidence_invalid');
    }
    const paymentSignature = headers['payment-signature'] ?? headers['x-payment-signature'];
    await ctx.evidence.writeObservation('http/sc006-response-loss-client.json', 'sc006-response-loss-client', {
      schemaVersion: 'bef-http-observation/v1', boundary: 'actual-tool-http', operationId, variantId: 'response_loss',
      request: {
        method: 'POST', path,
        monotonicStartMs: requestStartedMonotonicMs,
        headers: {
          'idempotency-key': key,
          'authorization-present': true,
          'authorization-sha256': sha256Bytes(Buffer.from(headers.authorization ?? '', 'utf8')),
          'payment-signature-present': typeof paymentSignature === 'string',
          ...(paymentSignature ? { 'payment-signature-sha256': sha256Bytes(Buffer.from(paymentSignature, 'utf8')) } : {}),
        },
        body: purchaseBody,
      },
      response: { transportError: 'connection_closed', relayUpstreamStatus: relayEvent.upstreamStatus, monotonicObservedMs: responseObservedMonotonicMs },
    });
    await ctx.evidence.writeObservation('http/sc006-response-loss-relay.json', 'sc006-response-loss-relay', {
      ...relayEvent,
      boundary: 'probe-owned-response-loss-relay',
      operationId,
      variantId: 'response_loss',
    });
  };
}

export async function retrySc006ReceiptRead<T>(
  readReceipt: (attempt: number) => Promise<T>,
  pause: (durationMs: number) => Promise<void> = (durationMs) => new Promise<void>((resolve) => setTimeout(resolve, durationMs)),
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 24; attempt += 1) {
    try {
      return await readReceipt(attempt + 1);
    } catch (error) {
      lastError = error;
      const receiptNotVisible = error instanceof Error && error.message === 'probe_rpc_receipt_missing';
      const localBoundaryTransientDenial = error instanceof RpcReadOnlyBoundaryMethodDeniedError
        && error.endpointBoundary === 'local-chain-readonly-proxy'
        && error.method === 'eth_getTransactionReceipt'
        && error.rpcCode === -32601;
      if (!receiptNotVisible && !localBoundaryTransientDenial) throw error;
      if (attempt + 1 < 24) await pause(250);
    }
  }
  throw lastError instanceof Error ? lastError : new Error('probe_sc006_independent_receipt_timeout');
}

async function sc006ReadIndependentReceipt(ctx: ProbeContext, operationId: string, transactionHash: string, variantId: string) {
  return await retrySc006ReceiptRead((attempt) => ctx.rpc.receipt({
    url: ctx.env.localRpcUrl,
    boundary: 'local-chain-readonly-proxy',
    transactionHash,
    operationId,
    variantId,
    label: `sc006-${variantId}-independent-receipt-${attempt}`,
  }));
}

export async function runScenario006(ctx: ProbeContext): Promise<ScenarioExecution> {
  await verifyPinnedBlocks(ctx, 'sc006-before');
  const session = await startGeneration(ctx, 'canonical', 'sc006');

  await runSc006InvalidPayment(ctx, session, 'wrong_domain');
  await runSc006InvalidPayment(ctx, session, 'amount_mismatch');

  const key = randomUUID();
  const challenge = await callChallenge(ctx, session, {
    label: 'sc006-missing-receipt-challenge', idempotencyKey: key, variantId: 'missing_receipt',
  });
  const signed = await createSignedPayload(session.signer, challenge.declaration, challenge.requirements);
  const payTo = challenge.requirements.payTo as `0x${string}`;
  const payerBefore = await readBalance(ctx, session, session.payerAddress, 'sc006-missing-receipt-payer-before', challenge.operationId, 'missing_receipt');
  const payToBefore = await readBalance(ctx, session, payTo, 'sc006-missing-receipt-payto-before', challenge.operationId, 'missing_receipt');
  const arm = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/sc006/receipt-read-fault/arm',
    label: 'sc006-missing-receipt-fault-arm', operationId: challenge.operationId, variantId: 'missing_receipt',
    body: { operationId: challenge.operationId, generationId: session.generationId, ttlMs: 10_000 },
  });
  if (arm.status !== 200 || sc006Record(arm.body, 'fault_arm').operationId !== challenge.operationId) {
    throw new Error('probe_sc006_receipt_fault_arm_failed');
  }
  const failedReceiptResponse = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key,
    variantId: 'missing_receipt',
    label: 'sc006-missing-receipt-original-payment',
    extraHeaders: signed.headers,
  });
  if (failedReceiptResponse.status !== 502) throw new Error(`probe_sc006_expected_unknown_settlement_${failedReceiptResponse.status}`);
  const unknownRows = await snapshotOperation(ctx, session, challenge.operationId, 'sc006-missing-receipt-after-unavailable', 'missing_receipt', key);
  const unknownOperation = sc006Operation(unknownRows, challenge.operationId);
  const unknownPayment = unknownRows.payments.filter((row) => String(row.operation_id) === challenge.operationId);
  const transactionHash = String(unknownPayment[0]?.transaction_hash ?? unknownOperation.transaction_hash ?? '');
  if (String(unknownOperation.status) !== 'settlement_unknown' || String(unknownOperation.receipt_status) !== 'unknown'
    || unknownPayment.length !== 1 || String(unknownPayment[0]?.receipt_status) !== 'unknown'
    || !/^0x[0-9a-f]{64}$/i.test(transactionHash)) throw new Error('probe_sc006_unknown_original_state_invalid');
  if (unknownRows.deliveries.some((row) => String(row.operation_id) === challenge.operationId)) {
    throw new Error('probe_sc006_unknown_original_delivered');
  }
  const unverifiedRetry = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key, variantId: 'missing_receipt',
    label: 'sc006-missing-receipt-unverified-same-operation-retry',
  });
  if (unverifiedRetry.status !== 409) throw new Error(`probe_sc006_unverified_retry_was_not_withheld_${unverifiedRetry.status}`);
  const afterUnverifiedRetry = await snapshotOperation(
    ctx, session, challenge.operationId, 'sc006-missing-receipt-after-unknown-retry', 'missing_receipt', key,
  );
  const stillUnknown = sc006Operation(afterUnverifiedRetry, challenge.operationId);
  const stillUnknownPayments = afterUnverifiedRetry.payments.filter((row) => String(row.operation_id) === challenge.operationId);
  if (String(stillUnknown.status) !== 'settlement_unknown' || String(stillUnknown.receipt_status) !== 'unknown'
    || String(stillUnknown.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || stillUnknownPayments.length !== 1
    || String(stillUnknownPayments[0]?.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || afterUnverifiedRetry.deliveries.some((row) => String(row.operation_id) === challenge.operationId)) {
    throw new Error('probe_sc006_unverified_retry_changed_original_settlement');
  }

  const faultStatus = await sc006FacilitatorRequest(ctx, {
    method: 'GET', path: `/internal/admin/sc006/receipt-read-fault/status/${challenge.operationId}`,
    label: 'sc006-missing-receipt-fault-status', operationId: challenge.operationId, variantId: 'missing_receipt',
  });
  const fault = sc006Record(faultStatus.body, 'fault_status');
  const broadcastHashes = Array.isArray(fault.broadcastHashes) ? fault.broadcastHashes : [];
  if (faultStatus.status !== 200 || fault.applied !== true || fault.faultedReads !== 1
    || String(fault.transactionHash).toLowerCase() !== transactionHash.toLowerCase()
    || broadcastHashes.length !== 1 || String(broadcastHashes[0]).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('probe_sc006_receipt_fault_not_bound_to_original_broadcast');
  }
  const originalReceipt = await sc006ReadIndependentReceipt(ctx, challenge.operationId, transactionHash, 'missing_receipt');
  if (originalReceipt.status.toLowerCase() !== '0x1') throw new Error('probe_sc006_independent_receipt_not_success');
  const transfers = transferEvents(originalReceipt, challenge.requirements.asset);
  const amount = BigInt(challenge.requirements.amount);
  if (transfers.filter((item) => item.from.toLowerCase() === session.payerAddress.toLowerCase()
    && item.to.toLowerCase() === payTo.toLowerCase() && item.amount === amount).length !== 1) {
    throw new Error('probe_sc006_original_transfer_missing');
  }

  const restored = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/sc006/receipt-read-fault/restore',
    label: 'sc006-missing-receipt-fault-restore', operationId: challenge.operationId, variantId: 'missing_receipt',
    body: { operationId: challenge.operationId, generationId: session.generationId },
  });
  const restoredBody = sc006Record(restored.body, 'fault_restore');
  if (restored.status !== 200 || restoredBody.restored !== true || restoredBody.applied !== true
    || String(restoredBody.transactionHash).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('probe_sc006_receipt_fault_restore_failed');
  }
  const reconciliation = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/reconcile-original-settlement',
    label: 'sc006-missing-receipt-original-reconciliation', operationId: challenge.operationId, variantId: 'missing_receipt',
    body: { operationId: challenge.operationId },
  });
  const reconciliationBody = sc006Record(reconciliation.body, 'reconciliation');
  if (reconciliation.status !== 200 || reconciliationBody.accepted !== true
    || reconciliationBody.reasonCode !== 'original_settlement_reconciled') {
    throw new Error('probe_sc006_original_settlement_reconciliation_failed');
  }
  const settledRows = await snapshotOperation(ctx, session, challenge.operationId, 'sc006-after-original-reconciliation', 'response_loss', key);
  const settledOperation = sc006Operation(settledRows, challenge.operationId);
  if (String(settledOperation.status) !== 'settled' || String(settledOperation.receipt_status) !== 'success'
    || String(settledOperation.transaction_hash).toLowerCase() !== transactionHash.toLowerCase()
    || settledRows.deliveries.some((row) => String(row.operation_id) === challenge.operationId)) {
    throw new Error('probe_sc006_reconciliation_state_invalid');
  }

  const responseLossAttempt = await prepareSc006ResponseLoss(ctx, session, challenge.operationId, key);
  const responseLossRequest = responseLossAttempt();
  const duplicateRequestsPromise = Promise.all([1, 2].map((index) => participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key, variantId: 'concurrent_duplicate',
    label: `sc006-concurrent-duplicate-${index}`,
  })));
  const [, duplicateRequests] = await Promise.all([responseLossRequest, duplicateRequestsPromise]);
  for (const response of duplicateRequests) {
    requireStatus(response, 200, 'sc006_concurrent_duplicate');
    if ((response.operationId ?? bodyOperationId(response.body)) !== challenge.operationId) {
      throw new Error('probe_sc006_duplicate_operation_identity_changed');
    }
  }
  const firstBody = sc006Record(duplicateRequests[0]?.body, 'duplicate_response');
  const secondBody = sc006Record(duplicateRequests[1]?.body, 'duplicate_response');
  if (firstBody.resourceId !== secondBody.resourceId || firstBody.contentHash !== secondBody.contentHash
    || firstBody.contentBytes !== secondBody.contentBytes) throw new Error('probe_sc006_duplicate_body_mismatch');
  const resource = await writeCanonicalResourceEvidence(ctx, challenge.operationId, firstBody, ctx.runtime.manifest);
  const settlementProof = await proveSettlement(
    ctx, session, challenge.operationId, key, challenge.requirements,
    payerBefore, payToBefore, 'sc006-after-concurrent-duplicate', 'concurrent_duplicate',
  );
  const settleObservations = settlementProof.rows.x402Observations.filter((row) =>
    String(row.operation_id) === challenge.operationId && String(row.phase) === 'settle');
  const settleObservationIds = settleObservations.map((row) => String(row.observation_id));
  const settleRequestHashes = settleObservations.map((row) => String(row.request_sha256).trim().toLowerCase());
  const settleVariantIds = settleObservations.map((row) => String(row.variant_id));
  const settleRequests = settleObservations.map((row) => JSON.stringify(row.safe_request));
  const settleHashesAreBound = settleObservations.every((row) =>
    row.transaction_hash == null || String(row.transaction_hash).toLowerCase() === transactionHash.toLowerCase());
  const settleOutcomesAreKnown = settleObservations.every((row) => row.outcome === 'unknown' || row.outcome === 'success');
  const settleRequirementsArePinned = settleObservations.every((row) => {
    const request = row.safe_request as Record<string, unknown> | null;
    const requirements = request?.paymentRequirements as Record<string, unknown> | undefined;
    return Boolean(requirements)
      && requirements?.scheme === challenge.requirements.scheme
      && requirements?.network === challenge.requirements.network
      && String(requirements?.asset).toLowerCase() === String(challenge.requirements.asset).toLowerCase()
      && String(requirements?.amount) === String(challenge.requirements.amount)
      && String(requirements?.payTo).toLowerCase() === String(challenge.requirements.payTo).toLowerCase();
  });
  if (settlementProof.transactionHash.toLowerCase() !== transactionHash.toLowerCase()
    || settlementProof.rows.deliveries.filter((row) => String(row.operation_id) === challenge.operationId).length !== 1
    || settleObservations.length < 1 || settleObservations.length > 2
    || settleObservationIds.some((id) => !id || id === 'undefined') || new Set(settleObservationIds).size !== settleObservationIds.length
    || settleVariantIds.some((variant) => !variant || variant === 'undefined') || new Set(settleVariantIds).size !== 1
    || settleRequestHashes.some((hash) => !/^[0-9a-f]{64}$/.test(hash)) || new Set(settleRequestHashes).size !== 1
    || new Set(settleRequests).size !== 1 || !settleOutcomesAreKnown
    || !settleHashesAreBound || !settleObservations.some((row) => String(row.transaction_hash ?? '').toLowerCase() === transactionHash.toLowerCase())
    || !settleRequirementsArePinned) {
    throw new Error('probe_sc006_duplicate_created_new_settlement_or_delivery');
  }
  const delivery = settlementProof.rows.deliveries.find((row) => String(row.operation_id) === challenge.operationId);
  if (!delivery || String(delivery.resource_id) !== ctx.runtime.manifest.x402.resourceId
    || String(delivery.content_sha256).toLowerCase() !== resource.contentHash.toLowerCase()
    || BigInt(String(delivery.content_bytes)) !== BigInt(resource.resourceBytes.byteLength)) {
    throw new Error('probe_sc006_pinned_delivery_mismatch');
  }

  const reusedKey = randomUUID();
  const reusedChallenge = await callChallenge(ctx, session, {
    label: 'sc006-reused-authorization-challenge', idempotencyKey: reusedKey, variantId: 'reused_authorization',
  });
  const reusedPayerBefore = await readBalance(ctx, session, session.payerAddress, 'sc006-reused-payer-before', reusedChallenge.operationId, 'reused_authorization');
  const reusedPayToBefore = await readBalance(ctx, session, payTo, 'sc006-reused-payto-before', reusedChallenge.operationId, 'reused_authorization');
  const reusedResponse = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: reusedKey, variantId: 'reused_authorization',
    label: 'sc006-reused-authorization-submission', extraHeaders: signed.headers,
  });
  requireClientError(reusedResponse, 'sc006_reused_authorization');
  const reusedRows = await snapshotOperation(ctx, session, reusedChallenge.operationId, 'sc006-reused-authorization-denial', 'reused_authorization', reusedKey);
  const reusedOperation = sc006Operation(reusedRows, reusedChallenge.operationId);
  if (!['rejected', 'reverted'].includes(String(reusedOperation.status))
    || reusedRows.payments.some((row) => String(row.operation_id) === reusedChallenge.operationId && String(row.receipt_status) === 'success')
    || reusedRows.deliveries.some((row) => String(row.operation_id) === reusedChallenge.operationId)) {
    throw new Error('probe_sc006_reused_authorization_effectful');
  }
  const reusedPayerAfter = await readBalance(ctx, session, session.payerAddress, 'sc006-reused-payer-after', reusedChallenge.operationId, 'reused_authorization');
  const reusedPayToAfter = await readBalance(ctx, session, payTo, 'sc006-reused-payto-after', reusedChallenge.operationId, 'reused_authorization');
  if (reusedPayerBefore !== reusedPayerAfter || reusedPayToBefore !== reusedPayToAfter) {
    throw new Error('probe_sc006_reused_authorization_balance_changed');
  }

  return { environment: { envId: session.envId, generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress } } };
}

type Sc008Rows = {
  operation: Record<string, unknown>[];
  generation: Record<string, unknown>[];
  payment: Record<string, unknown>[];
  selectedExecution: Record<string, unknown>[];
  cost: Record<string, unknown>[];
};

function sc008Rows(payload: Record<string, unknown>): Sc008Rows {
  const rows = recordOf(payload.rows);
  if (!rows) throw new Error('probe_sc008_cost_rows_invalid');
  const names = ['operation', 'generation', 'payment', 'selectedExecution', 'cost'] as const;
  const result: Partial<Sc008Rows> = {};
  for (const name of names) {
    const value = rows[name];
    if (!Array.isArray(value) || value.some((entry) => !recordOf(entry))) {
      throw new Error(`probe_sc008_cost_${name}_rows_invalid`);
    }
    result[name] = value as Record<string, unknown>[];
  }
  if (!result.operation || !result.generation || !result.payment || !result.selectedExecution || !result.cost) {
    throw new Error('probe_sc008_cost_rows_incomplete');
  }
  return result as Sc008Rows;
}

async function captureSc008PaidPurchase(
  ctx: ProbeContext,
  session: GenerationSession,
  variantId: 'sponsored_settlement' | 'embedded_fee',
): Promise<void> {
  const key = randomUUID();
  const challenge = await callChallenge(ctx, session, {
    label: `sc008-${variantId}-challenge`, idempotencyKey: key, variantId: null,
  });
  const signed = await createSignedPayload(session.signer, challenge.declaration, challenge.requirements);
  const payTo = challenge.requirements.payTo as `0x${string}`;
  const payerBefore = await readBalance(ctx, session, session.payerAddress, `sc008-${variantId}-payer-before`, challenge.operationId, variantId);
  const payToBefore = await readBalance(ctx, session, payTo, `sc008-${variantId}-payto-before`, challenge.operationId, variantId);
  const response = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key, variantId, label: `sc008-${variantId}-signed-purchase`,
    extraHeaders: signed.headers, includeRawResponseBytes: true,
  });
  requireStatus(response, 200, `sc008_${variantId}`);
  const operationId = response.operationId ?? bodyOperationId(response.body) ?? challenge.operationId;
  if (operationId !== challenge.operationId) throw new Error(`probe_sc008_${variantId}_operation_identity_changed`);
  const settlement = readSettlementHeader(session.signer.httpClient, response.headers);
  if (!settlement || settlement.success !== true) throw new Error(`probe_sc008_${variantId}_settlement_header_missing`);
  const settled = await proveSettlement(
    ctx, session, operationId, key, challenge.requirements,
    payerBefore, payToBefore, `sc008-${variantId}-settlement`, variantId,
  );
  if (settled.transactionHash.toLowerCase() !== settlement.transaction.toLowerCase()) {
    throw new Error(`probe_sc008_${variantId}_settlement_hash_conflict`);
  }

  const dbProof = await observeSc008CostOperation(ctx, {
    envId: session.envId, generationId: session.generationId, operationId,
  }, variantId, `${variantId}-${operationId}`);
  const rows = sc008Rows(dbProof);
  const cost = rows.cost.length === 1 ? rows.cost[0]! : null;
  const operation = rows.operation.length === 1 ? rows.operation[0]! : null;
  const payment = rows.payment.length === 1 ? rows.payment[0]! : null;
  const facilitator = typeof payment?.facilitator_address === 'string' ? payment.facilitator_address : null;
  const receiptBlockNumber = typeof cost?.receipt_block_number === 'string' ? cost.receipt_block_number : null;
  if (!cost || !operation || !payment || !facilitator || !receiptBlockNumber
      || cost.payer_role !== 'facilitator' || cost.receipt_status !== 'success'
      || cost.transaction_hash?.toString().toLowerCase() !== settled.transactionHash.toLowerCase()
      || facilitator.toLowerCase() !== cost.payer_address?.toString().toLowerCase()
      || payment.transaction_hash?.toString().toLowerCase() !== settled.transactionHash.toLowerCase()
      || operation.status !== 'delivered' || operation.receipt_status !== 'success'
      || !/^(?:0|[1-9][0-9]*)$/.test(String(cost.gas_cost_wei ?? ''))
      || !/^(?:0|[1-9][0-9]*)$/.test(String(cost.modeled_gas_fee_usdc_units ?? ''))
      || cost.payer_native_balance_before_wei === null || cost.payer_native_balance_after_wei === null) {
    throw new Error(`probe_sc008_${variantId}_durable_cost_observation_invalid`);
  }

  const raw = await observeSc008OriginalCostRpc(ctx, {
    operationId, variantId, transactionHash: settled.transactionHash as `0x${string}`,
    facilitatorPayer: facilitator.toLowerCase() as `0x${string}`,
    participantPayer: session.payerAddress,
    receiptMode: 'skip', receiptBlockNumber,
    label: `sc008-${variantId}-sponsor-history`,
  });
  const paymentAmountUnits = String(payment.amount_units);
  const gasFeeUsdcUnits = String(cost.modeled_gas_fee_usdc_units);
  const participantHistory = recordOf(raw.participantHistory);
  const participantBeforeWei = typeof participantHistory?.beforeBalance === 'string' ? participantHistory.beforeBalance : null;
  const participantAfterWei = typeof participantHistory?.afterBalance === 'string' ? participantHistory.afterBalance : null;
  const participantBeforeBlockHash = typeof participantHistory?.beforeBlockHash === 'string' ? participantHistory.beforeBlockHash.toLowerCase() : null;
  const participantAfterBlockHash = typeof participantHistory?.afterBlockHash === 'string' ? participantHistory.afterBlockHash.toLowerCase() : null;
  if (!participantHistory || !participantBeforeWei || !participantAfterWei
      || BigInt(participantBeforeWei) !== BigInt(participantAfterWei)
      || participantBeforeBlockHash !== String(cost.payer_native_balance_before_block_hash).toLowerCase()
      || participantAfterBlockHash !== String(cost.receipt_block_hash).toLowerCase()) {
    throw new Error(`probe_sc008_${variantId}_participant_native_fee_not_zero`);
  }
  const serviceTransfers = transferEvents(settled.receipt, String(payment.asset_address)).filter((event) =>
    event.from.toLowerCase() === String(payment.payer_address).toLowerCase()
    && event.to.toLowerCase() === facilitator.toLowerCase()
    && event.amount === BigInt(paymentAmountUnits));
  if (serviceTransfers.length !== 1) throw new Error(`probe_sc008_${variantId}_service_transfer_component_invalid`);
  const costAllocation = {
    serviceComponent: {
      assetAddress: String(payment.asset_address).toLowerCase(),
      amountUsdcUnits: paymentAmountUnits,
      payerAddress: String(payment.payer_address).toLowerCase(),
      recipientAddress: facilitator.toLowerCase(),
      transactionHash: settled.transactionHash.toLowerCase(),
      receiptTransferCount: serviceTransfers.length,
    },
    gasComponent: {
      asset: 'ETH',
      modeledUsdcUnits: gasFeeUsdcUnits,
      payerAddress: String(cost.payer_address).toLowerCase(),
      payerRole: cost.payer_role,
      transactionHash: settled.transactionHash.toLowerCase(),
      receiptStatus: cost.receipt_status,
    },
    participantExpenseUsdcUnits: paymentAmountUnits,
    participantGasFeeUsdcUnits: '0',
    participantNativeBalanceProof: {
      payerAddress: session.payerAddress.toLowerCase(),
      beforeBalanceWei: BigInt(participantBeforeWei).toString(),
      beforeBlockHash: participantBeforeBlockHash,
      beforeBlockNumber: BigInt(String(participantHistory.beforeBlockNumber)).toString(),
      afterBalanceWei: BigInt(participantAfterWei).toString(),
      afterBlockHash: participantAfterBlockHash,
      afterBlockNumber: BigInt(String(participantHistory.afterBlockNumber)).toString(),
      deltaWei: '0',
    },
    facilitatorOperatingGasFeeUsdcUnits: gasFeeUsdcUnits,
    countedServiceComponents: 1,
    countedGasComponents: 1,
  };
  await ctx.evidence.writeObservation(`costs/${operationId}-${variantId}-summary.json`, `sc008-${variantId}-cost-summary`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'benchmark-environment-transaction-costs',
    scenarioId: 'BEF-SC-008', queryName: 'sc008-cost-component-allocation', operationId, variantId,
    envId: session.envId, generationId: session.generationId,
    manifestSha256: ctx.runtime.manifestSha256,
    transactionHash: settled.transactionHash,
    payerRole: cost.payer_role, payerAddress: cost.payer_address,
    serviceAmountUnits: payment.amount_units,
    receiptStatus: cost.receipt_status, gasUsed: cost.gas_used,
    effectiveGasPriceWei: cost.effective_gas_price_wei, gasCostWei: cost.gas_cost_wei,
    modeledGasFeeUsdcUnits: cost.modeled_gas_fee_usdc_units,
    selectedPrincipalUnits: cost.selected_principal_units,
    observedPrincipalUnits: cost.observed_principal_units,
    baseL1Fee: cost.base_l1_fee_status, rawTransactionObserved: raw.transaction !== null,
    rawReceiptCapturedBySettlementProof: true, sponsorHistoryObserved: Boolean(raw.sponsorHistory),
    costAllocation,
  });
}

async function captureSc008MissingReceipt(ctx: ProbeContext): Promise<void> {
  const session = await startGeneration(ctx, 'canonical', 'sc008-missing-receipt');
  const key = randomUUID();
  const challenge = await callChallenge(ctx, session, {
    label: 'sc008-missing-receipt-challenge', idempotencyKey: key, variantId: null,
  });
  const signed = await createSignedPayload(session.signer, challenge.declaration, challenge.requirements);
  const arm = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/sc006/receipt-read-fault/arm',
    label: 'sc008-missing-receipt-fault-arm', operationId: challenge.operationId, variantId: 'missing_receipt',
    body: { operationId: challenge.operationId, generationId: session.generationId, ttlMs: 10_000 },
  });
  if (arm.status !== 200 || sc006Record(arm.body, 'sc008_fault_arm').operationId !== challenge.operationId) {
    throw new Error('probe_sc008_receipt_fault_arm_failed');
  }
  const response = await participantRequest(ctx, session, {
    method: 'POST', path: `/tools/${session.envId}/purchase`,
    body: { resourceId: ctx.runtime.manifest.x402.resourceId, offerId: 'canonical' },
    idempotencyKey: key, variantId: 'missing_receipt',
    label: 'sc008-missing-receipt-signed-purchase', extraHeaders: signed.headers,
  });
  if (response.status !== 502) throw new Error(`probe_sc008_expected_missing_receipt_${response.status}`);
  const rowsAfterFailure = await snapshotOperation(
    ctx, session, challenge.operationId, 'sc008-missing-receipt-before-observation', 'missing_receipt', key,
  );
  const operation = sc006Operation(rowsAfterFailure, challenge.operationId);
  const payment = rowsAfterFailure.payments.filter((row) => String(row.operation_id) === challenge.operationId);
  const transactionHash = String(payment[0]?.transaction_hash ?? operation.transaction_hash ?? '');
  if (operation.status !== 'settlement_unknown' || operation.receipt_status !== 'unknown'
      || payment.length !== 1 || payment[0]?.receipt_status !== 'unknown'
      || !/^0x[0-9a-f]{64}$/i.test(transactionHash)
      || rowsAfterFailure.deliveries.some((row) => String(row.operation_id) === challenge.operationId)) {
    throw new Error('probe_sc008_missing_receipt_state_not_unknown');
  }
  const unknownProof = await observeSc008CostOperation(ctx, {
    envId: session.envId, generationId: session.generationId, operationId: challenge.operationId,
  }, 'missing_receipt', `missing-receipt-unknown-${challenge.operationId}`);
  const unknownRows = sc008Rows(unknownProof);
  const unknownCost = unknownRows.cost.length === 1 ? unknownRows.cost[0]! : null;
  const durablePayment = unknownRows.payment.length === 1 ? unknownRows.payment[0]! : null;
  const facilitator = typeof durablePayment?.facilitator_address === 'string' ? durablePayment.facilitator_address : null;
  if (!unknownCost || !durablePayment || !facilitator || unknownCost.receipt_status !== 'unknown'
      || unknownCost.payer_role !== 'facilitator'
      || unknownCost.transaction_hash?.toString().toLowerCase() !== transactionHash.toLowerCase()
      || facilitator.toLowerCase() !== unknownCost.payer_address?.toString().toLowerCase()
      || unknownCost.gas_used !== null || unknownCost.effective_gas_price_wei !== null
      || unknownCost.gas_cost_wei !== null || unknownCost.modeled_gas_fee_usdc_units !== null
      || unknownCost.receipt_evidence_json !== null || unknownCost.observed_principal_units !== null) {
    throw new Error('probe_sc008_missing_receipt_cost_was_not_unknown');
  }
  await observeSc008OriginalCostRpc(ctx, {
    operationId: challenge.operationId, variantId: 'missing_receipt',
    transactionHash: transactionHash as `0x${string}`, receiptMode: 'skip',
    label: 'sc008-missing-receipt-original-transaction',
  });

  const faultStatus = await sc006FacilitatorRequest(ctx, {
    method: 'GET', path: `/internal/admin/sc006/receipt-read-fault/status/${challenge.operationId}`,
    label: 'sc008-missing-receipt-fault-status', operationId: challenge.operationId, variantId: 'missing_receipt',
  });
  const fault = sc006Record(faultStatus.body, 'sc008_fault_status');
  const broadcastHashes = Array.isArray(fault.broadcastHashes) ? fault.broadcastHashes : [];
  if (faultStatus.status !== 200 || fault.applied !== true || fault.faultedReads !== 1
      || String(fault.transactionHash).toLowerCase() !== transactionHash.toLowerCase()
      || broadcastHashes.length !== 1 || String(broadcastHashes[0]).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('probe_sc008_receipt_fault_not_bound_to_original_hash');
  }
  await ctx.evidence.writeObservation(`costs/${challenge.operationId}-receipt-read-fault.json`, 'sc008-receipt-read-fault-proof', {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'facilitator-original-receipt-read-fault',
    queryName: 'sc008-original-receipt-read-fault-proof', operationId: challenge.operationId,
    variantId: 'missing_receipt', responseStatus: faultStatus.status,
    transactionHash, applied: fault.applied, faultedReads: fault.faultedReads,
    broadcastHashes,
  });
  const restored = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/sc006/receipt-read-fault/restore',
    label: 'sc008-missing-receipt-fault-restore', operationId: challenge.operationId, variantId: 'missing_receipt',
    body: { operationId: challenge.operationId, generationId: session.generationId },
  });
  const restoredBody = sc006Record(restored.body, 'sc008_fault_restore');
  if (restored.status !== 200 || restoredBody.restored !== true || restoredBody.applied !== true
      || String(restoredBody.transactionHash).toLowerCase() !== transactionHash.toLowerCase()) {
    throw new Error('probe_sc008_receipt_fault_restore_failed');
  }

  const original = await observeSc008OriginalCostRpc(ctx, {
    operationId: challenge.operationId, variantId: 'missing_receipt_reconciled',
    transactionHash: transactionHash as `0x${string}`,
    facilitatorPayer: facilitator.toLowerCase() as `0x${string}`,
    label: 'sc008-missing-receipt-reconciliation',
  });
  const receipt = recordOf(original.receipt);
  if (!receipt || !['0x1', '0x01', '1'].includes(String(receipt.status).toLowerCase())) {
    throw new Error('probe_sc008_original_receipt_not_recovered');
  }
  const reconciliation = await sc006FacilitatorRequest(ctx, {
    method: 'POST', path: '/internal/admin/reconcile-original-settlement',
    label: 'sc008-missing-receipt-original-reconciliation', operationId: challenge.operationId,
    variantId: 'missing_receipt_reconciled', body: { operationId: challenge.operationId },
  });
  const reconciliationBody = sc006Record(reconciliation.body, 'sc008_reconciliation');
  if (reconciliation.status !== 200 || reconciliationBody.accepted !== true
      || reconciliationBody.reasonCode !== 'original_settlement_reconciled') {
    throw new Error('probe_sc008_original_hash_reconciliation_failed');
  }
  const finalProof = await observeSc008CostOperation(ctx, {
    envId: session.envId, generationId: session.generationId, operationId: challenge.operationId,
  }, 'missing_receipt_reconciled', `missing-receipt-final-${challenge.operationId}`);
  const finalRows = sc008Rows(finalProof);
  const finalCost = finalRows.cost.length === 1 ? finalRows.cost[0]! : null;
  const finalOperation = finalRows.operation.length === 1 ? finalRows.operation[0]! : null;
  if (!finalCost || !finalOperation || finalCost.receipt_status !== 'success'
      || finalCost.transaction_hash?.toString().toLowerCase() !== transactionHash.toLowerCase()
      || finalOperation.status !== 'settled' || finalOperation.receipt_status !== 'success'
      || finalCost.gas_cost_wei === null || finalCost.modeled_gas_fee_usdc_units === null) {
    throw new Error('probe_sc008_reconciled_cost_not_receipt_backed');
  }
}

export async function runScenario008(ctx: ProbeContext): Promise<ScenarioExecution> {
  await runSc008ParticipantCostActions(ctx);
  await captureSc008MissingReceipt(ctx);
  const session = await startGeneration(ctx, 'canonical', 'sc008-sponsored-costs');
  await captureSc008PaidPurchase(ctx, session, 'sponsored_settlement');
  await captureSc008PaidPurchase(ctx, session, 'embedded_fee');
  return {
    environment: {
      envId: session.envId,
      generation: { generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    },
  };
}
