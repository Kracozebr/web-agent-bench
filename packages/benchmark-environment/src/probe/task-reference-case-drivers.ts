/**
 * Dedicated public-tool reference observations for BTS S2 and M1.
 * These captures prove observed tool/chain/application facts only. They never
 * create a BTS release or claim a task score.
 */
import { createHash, randomUUID } from 'node:crypto';
import pg from 'pg';
import { encodeFunctionData, parseAbi } from 'viem';
import type { Address } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import { loadPinnedResources } from '../resource.js';
import { apiPath, newParticipantId } from './environment.js';
import { sanitizeValue } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { createEphemeralSigner, createSignedPayload, readSettlementHeader } from './x402.js';
import { transferEvents } from './rpc.js';
import { projectDeliveryEnvelope, projectM1PaymentRequirements, projectS2OfferObjective } from './task-reference-cases.js';

const { Pool } = pg;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const BALANCE_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
]);

export type CaseDatabaseFacts = {
  counts: {
    operations: string;
    offerOperations: string;
    purchaseOperations: string;
    nonOfferOperations: string;
    payments: string;
    deliveries: string;
    denials: string;
    x402Observations: string;
    selectedExecutions: string;
    selectedExecutionEvents: string;
    transactionCosts: string;
    participantCosts: string;
  };
  operations: Array<Record<string, unknown>>;
  payments: Array<Record<string, unknown>>;
  deliveries: Array<Record<string, unknown>>;
  transactionCosts: Array<Record<string, unknown>>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_reference_${name}_missing`);
  return value;
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Decode one ABI uint256 return word without rejecting leading zero bytes. */
export function parseAbiUint256Word(value: unknown): string {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value)) {
    throw new Error('task_reference_abi_uint256_word_invalid');
  }
  return BigInt(value).toString();
}

function safeCount(value: string, name: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`task_reference_${name}_count_invalid`);
  }
  return Number(value);
}

export async function readRpc<T>(ctx: ProbeContext, input: {
  method: string;
  params: unknown[];
  requestedBlock?: string;
  operationId: string | null;
  variantId: string;
  label: string;
}): Promise<T> {
  const { result } = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl,
    endpointBoundary: 'local-chain-readonly-proxy',
    environmentId: ctx.env.envId,
    method: input.method,
    params: input.params,
    ...(input.requestedBlock === undefined ? {} : { requestedBlock: input.requestedBlock }),
    operationId: input.operationId,
    variantId: input.variantId,
    label: input.label,
  });
  return result;
}

export async function readTokenValue(ctx: ProbeContext, input: {
  token: string;
  functionName: 'balanceOf' | 'allowance';
  args: readonly string[];
  blockTag: string;
  operationId: string | null;
  variantId: string;
  label: string;
}): Promise<string> {
  if (!ADDRESS.test(input.token) || input.args.some((address) => !ADDRESS.test(address))) {
    throw new Error('task_reference_chain_address_invalid');
  }
  const token = input.token as Address;
  const owner = input.args[0] as Address;
  const data = input.functionName === 'balanceOf'
    ? encodeFunctionData({ abi: BALANCE_ABI, functionName: 'balanceOf', args: [owner] })
    : encodeFunctionData({ abi: BALANCE_ABI, functionName: 'allowance', args: [owner, input.args[1] as Address] });
  const result = await readRpc<string>(ctx, {
    method: 'eth_call',
    params: [{ to: token, data }, input.blockTag],
    requestedBlock: input.blockTag,
    operationId: input.operationId,
    variantId: input.variantId,
    label: input.label,
  });
  return parseAbiUint256Word(result);
}

export async function readCaseState(ctx: ProbeContext, input: {
  session: GenerationSession;
  blockTag: string;
  blockHash: string;
  operationId: string | null;
  variantId: string;
  label: string;
}): Promise<Record<string, unknown>> {
  const manifest = ctx.runtime.manifest;
  const payer = input.session.payerAddress;
  const [payerNative, payerUsdc, payerWeth, usdcAllowance, wethAllowance] = await Promise.all([
    readRpc<string>(ctx, {
      method: 'eth_getBalance', params: [payer, input.blockTag], requestedBlock: input.blockTag,
      operationId: input.operationId, variantId: input.variantId, label: `${input.label}-payer-native`,
    }),
    readTokenValue(ctx, { token: manifest.contracts.usdc.address, functionName: 'balanceOf', args: [payer], blockTag: input.blockTag, operationId: input.operationId, variantId: input.variantId, label: `${input.label}-payer-usdc` }),
    readTokenValue(ctx, { token: manifest.contracts.weth.address, functionName: 'balanceOf', args: [payer], blockTag: input.blockTag, operationId: input.operationId, variantId: input.variantId, label: `${input.label}-payer-weth` }),
    readTokenValue(ctx, { token: manifest.contracts.usdc.address, functionName: 'allowance', args: [payer, manifest.contracts.swapRouter02.address], blockTag: input.blockTag, operationId: input.operationId, variantId: input.variantId, label: `${input.label}-usdc-router-allowance` }),
    readTokenValue(ctx, { token: manifest.contracts.weth.address, functionName: 'allowance', args: [payer, manifest.contracts.swapRouter02.address], blockTag: input.blockTag, operationId: input.operationId, variantId: input.variantId, label: `${input.label}-weth-router-allowance` }),
  ]);
  if (typeof payerNative !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(payerNative)) {
    throw new Error('task_reference_native_balance_invalid');
  }
  return {
    blockNumber: BigInt(input.blockTag).toString(),
    blockHash: input.blockHash.toLowerCase(),
    payerAddress: payer.toLowerCase(),
    payerNativeEthWei: BigInt(payerNative).toString(),
    payerUsdcUnits: payerUsdc,
    payerWethUnits: payerWeth,
    usdcRouterAllowanceUnits: usdcAllowance,
    wethRouterAllowanceUnits: wethAllowance,
  };
}

export async function startFreshCaseGeneration(ctx: ProbeContext, input: {
  caseId: 'h1' | 's2' | 's3' | 'm1' | 'm2' | 'h2' | 'u1' | 'h3' | 'm4';
  scenarioId: string;
  variantId: string;
  labelSuffix?: 'planning' | 'actual';
}): Promise<GenerationSession> {
  const labelSuffix = input.labelSuffix ? `-${input.labelSuffix}` : '';
  const previousGenerationId = ctx.primaryGeneration?.generationId ?? null;
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!ctx.capability.reset?.supported || !resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) {
    throw new Error(`task_reference_${input.caseId}_reset_route_unavailable`);
  }
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-reference-${input.caseId}${labelSuffix}-reset`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId: input.variantId,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_reference_${input.caseId}_reset_failed_${reset.status}`);

  const chainId = await readRpc<string>(ctx, {
    method: 'eth_chainId', params: [], operationId: null, variantId: input.variantId,
    label: `task-reference-${input.caseId}${labelSuffix}-chain-id`,
  });
  if (typeof chainId !== 'string' || BigInt(chainId) !== BigInt(ctx.runtime.manifest.local.chainId)) {
    throw new Error(`task_reference_${input.caseId}_chain_id_mismatch`);
  }
  const forkBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl,
    boundary: 'local-chain-readonly-proxy',
    blockNumber: ctx.runtime.manifest.local.forkBlock,
    operationId: null,
    variantId: input.variantId,
    label: `task-reference-${input.caseId}${labelSuffix}-fork-block`,
  });
  if (forkBlock.hash.toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()) {
    throw new Error(`task_reference_${input.caseId}_fork_identity_mismatch`);
  }

  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(input.scenarioId);
  const created = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-reference-${input.caseId}${labelSuffix}-generation`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId: input.variantId,
  });
  const body = isRecord(created.body) ? created.body : null;
  if (created.status < 200 || created.status >= 300 || !body) {
    throw new Error(`task_reference_${input.caseId}_generation_failed_${created.status}`);
  }
  const session: GenerationSession = {
    envId: requiredString(body.envId, 'env_id'),
    generationId: requiredString(body.generationId, 'generation_id'),
    participantId,
    payerAddress: signer.payerAddress,
    runToken: requiredString(body.runToken ?? (isRecord(body.participant) ? body.participant.runToken : undefined), 'run_token'),
    signer,
  };
  if (session.envId !== ctx.env.envId || String(body.payerAddress).toLowerCase() !== signer.payerAddress.toLowerCase()
    || previousGenerationId === session.generationId) {
    throw new Error(`task_reference_${input.caseId}_generation_identity_mismatch`);
  }
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  ctx.primarySession = session;
  await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId: input.variantId,
    label: `task-reference-${input.caseId}${labelSuffix}-generation-row`,
  });
  return session;
}

export async function readCaseDatabaseFacts(
  ctx: ProbeContext,
  session: Pick<GenerationSession, 'envId' | 'generationId'>,
  label: string,
  variantId: string,
): Promise<CaseDatabaseFacts> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl,
    max: 1,
    connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000,
    query_timeout: 8_000,
    application_name: `web-agent-bench-bef-reference-${label}`,
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operations, payments, deliveries, counts, transactionCosts] = await Promise.all([
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query(`SELECT operation_id::text,operation_kind,status,receipt_status,transaction_hash,
                           response_sha256,selected_offer_id,selected_amount_units::text,
                           selected_resource_id,selected_resource_sha256
                      FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id`,
        [session.envId, session.generationId]),
      client.query(`SELECT operation_id::text,payer_address,network,asset_address,amount_units::text,
                           facilitator_address,transaction_hash,receipt_status,token_delta_units::text,
                           payer_balance_before::text,payer_balance_after::text,
                           facilitator_balance_before::text,facilitator_balance_after::text
                      FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY observed_at,operation_id`,
        [session.envId, session.generationId]),
      client.query(`SELECT d.operation_id::text,d.resource_id,d.content_sha256,d.content_bytes::text
                      FROM bef_delivery d JOIN bef_operation o USING(operation_id)
                     WHERE o.env_id=$1 AND o.generation_id=$2::uuid ORDER BY d.delivered_at,d.operation_id`,
        [session.envId, session.generationId]),
      client.query(`SELECT
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid)::text AS operations,
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_kind='offer')::text AS offer_operations,
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_kind='purchase')::text AS purchase_operations,
        (SELECT count(*) FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_kind<>'offer')::text AS non_offer_operations,
        (SELECT count(*) FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid)::text AS payments,
        (SELECT count(*) FROM bef_delivery d JOIN bef_operation o USING(operation_id) WHERE o.env_id=$1 AND o.generation_id=$2::uuid)::text AS deliveries,
        (SELECT count(*) FROM bef_denial WHERE env_id=$1 AND generation_id=$2::uuid)::text AS denials,
        (SELECT count(*) FROM bef_x402_observation WHERE env_id=$1 AND generation_id=$2::uuid)::text AS x402_observations,
        (SELECT count(*) FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid)::text AS selected_executions,
        (SELECT count(*) FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid)::text AS selected_execution_events,
        (SELECT count(*) FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid)::text AS transaction_costs,
        (SELECT count(*) FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND payer_role='participant')::text AS participant_costs`,
        [session.envId, session.generationId]),
      client.query(`SELECT operation_id::text,transaction_hash,payer_address,payer_role,receipt_status,transaction_from,receipt_from,
                           gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,
                           modeled_gas_fee_usdc_units::text,fee_rate_numerator::text,fee_rate_denominator::text,
                           fee_policy_snapshot,manifest_sha256,receipt_block_number::text,receipt_block_hash,
                           base_l1_fee_status
                      FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash`,
        [session.envId, session.generationId]),
    ]);
    if (role.rows[0]?.role_name !== ctx.database.databaseRole || mode.rows[0]?.transaction_read_only !== 'on') {
      throw new Error(`task_reference_${label}_database_not_readonly`);
    }
    const countsRow = counts.rows[0];
    if (!countsRow) throw new Error(`task_reference_${label}_database_counts_missing`);
    const facts: CaseDatabaseFacts = {
      counts: {
        operations: countsRow.operations,
        offerOperations: countsRow.offer_operations,
        purchaseOperations: countsRow.purchase_operations,
        nonOfferOperations: countsRow.non_offer_operations,
        payments: countsRow.payments,
        deliveries: countsRow.deliveries,
        denials: countsRow.denials,
        x402Observations: countsRow.x402_observations,
        selectedExecutions: countsRow.selected_executions,
        selectedExecutionEvents: countsRow.selected_execution_events,
        transactionCosts: countsRow.transaction_costs,
        participantCosts: countsRow.participant_costs,
      },
      operations: operations.rows as Array<Record<string, unknown>>,
      payments: payments.rows as Array<Record<string, unknown>>,
      deliveries: deliveries.rows as Array<Record<string, unknown>>,
      transactionCosts: transactionCosts.rows as Array<Record<string, unknown>>,
    };
    await client.query('COMMIT');
    await ctx.evidence.writeObservation(`db/task-reference/${label}.json`, `task-reference-${label}`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: null,
      variantId, envId: session.envId, generationId: session.generationId,
      readOnly: true, databaseRole: ctx.database.databaseRole, transactionReadOnly: 'on',
      queryName: 'reference-case-operation-payment-delivery-cost-effect-census',
      rows: sanitizeValue(facts),
    });
    return facts;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && /^task_reference_[a-z0-9_]+$/.test(error.message)) throw error;
    throw new Error(`task_reference_${label}_database_observation_unavailable`);
  } finally {
    client.release();
    await pool.end();
  }
}

function effectCounts(counts: CaseDatabaseFacts['counts']): Record<string, string> {
  return {
    nonOfferOperations: counts.nonOfferOperations,
    purchases: counts.purchaseOperations,
    payments: counts.payments,
    deliveries: counts.deliveries,
    denials: counts.denials,
    x402Observations: counts.x402Observations,
    selectedExecutions: counts.selectedExecutions,
    selectedExecutionEvents: counts.selectedExecutionEvents,
    transactionCosts: counts.transactionCosts,
  };
}

function assertZeroEffects(counts: Record<string, string>, label: string): void {
  if (Object.values(counts).some((count) => count !== '0')) throw new Error(`task_reference_${label}_unexpected_effect`);
}

export async function latestBlock(ctx: ProbeContext, operationId: string | null, variantId: string, label: string): Promise<{ tag: string; number: string; hash: string }> {
  const tag = await readRpc<string>(ctx, { method: 'eth_blockNumber', params: [], operationId, variantId, label: `${label}-height` });
  if (typeof tag !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(tag)) throw new Error('task_reference_block_height_invalid');
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: tag,
    operationId, variantId, label: `${label}-block`,
  });
  return { tag, number: BigInt(tag).toString(), hash: block.hash.toLowerCase() };
}

/** Capture a free GET /offer and prove a complete same-block no-economic-effect interval. */
export async function captureS2ReadonlyOffer(ctx: ProbeContext, options: {
  resourceId?: string;
  expectedOfferId?: string;
  variantId?: string;
} = {}): Promise<Record<string, unknown>> {
  const variantId = options.variantId ?? (options.resourceId ? 'bts_s2_training_reference_capture' : 'bts_s2_reference_capture');
  const session = await startFreshCaseGeneration(ctx, { caseId: 's2', scenarioId: 'BEF-SC-004', variantId });
  const resource = options.resourceId
    ? ctx.runtime.manifest.x402.catalog?.find((entry) => entry.resourceId === options.resourceId)
    : ctx.runtime.manifest.x402.catalog?.find((entry) => entry.resourceId === ctx.runtime.manifest.x402.resourceId)
      ?? ctx.runtime.manifest.x402.catalog?.[0];
  if (!resource) throw new Error('task_reference_s2_pinned_resource_missing');
  if (options.expectedOfferId && !resource.offers.some((offer) => offer.id === options.expectedOfferId)) {
    throw new Error('task_reference_s2_expected_offer_missing');
  }
  const block = await latestBlock(ctx, null, variantId, 'task-reference-s2-interval');
  const stateBefore = await readCaseState(ctx, {
    session, blockTag: block.tag, blockHash: block.hash, operationId: null, variantId,
    label: 'task-reference-s2-state-before',
  });
  const databaseBefore = await readCaseDatabaseFacts(ctx, session, 's2-database-before', variantId);
  if (databaseBefore.counts.operations !== '0') throw new Error('task_reference_s2_generation_not_clean');
  assertZeroEffects(effectCounts(databaseBefore.counts), 's2_database_before');

  const idempotencyKey = randomUUID();
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-reference-s2-public-offer-read', method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/offer?resourceId=${encodeURIComponent(resource.resourceId)}`),
    headers: {
      authorization: `Bearer ${session.runToken}`,
      'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey,
      'content-type': 'application/json',
    },
    operationId: null, variantId,
  });
  if (response.status !== 200 || !isRecord(response.body)) throw new Error(`task_reference_s2_offer_http_failed_${response.status}`);
  const objective = projectS2OfferObjective({ response: response.body, pinnedResource: resource, paymentPolicy: ctx.runtime.manifest.x402 });
  if (options.expectedOfferId && objective.offerId !== options.expectedOfferId) throw new Error('task_reference_s2_observed_offer_mismatch');
  const operationId = requiredString(response.body.operationId, 's2_offer_operation_id');
  const databaseAfter = await readCaseDatabaseFacts(ctx, session, 's2-database-after', variantId);
  const blockAfterGet = await latestBlock(ctx, operationId, variantId, 'task-reference-s2-after-offer');
  const stateAfter = await readCaseState(ctx, {
    session, blockTag: blockAfterGet.tag, blockHash: blockAfterGet.hash, operationId, variantId,
    label: 'task-reference-s2-state-after',
  });
  const blockAtEnd = await latestBlock(ctx, operationId, variantId, 'task-reference-s2-interval-end');
  const offerRows = databaseAfter.operations.filter((operation) => operation.operation_id === operationId);
  const offerOperation = offerRows.length === 1 ? offerRows[0]! : null;
  const expectedResponseHash = sha256(JSON.stringify(response.body));
  const isAcceptedOfferRead = offerOperation?.operation_kind === 'offer' && offerOperation.status === 'accepted'
    && offerOperation.receipt_status === 'not_submitted' && offerOperation.transaction_hash === null
    && offerOperation.response_sha256 === expectedResponseHash;
  const stateUnchanged = JSON.stringify(stateBefore) === JSON.stringify(stateAfter);
  const beforeEffects = effectCounts(databaseBefore.counts);
  const afterEffects = effectCounts(databaseAfter.counts);
  assertZeroEffects(afterEffects, 's2_database_after');
  const blockStayedFixed = block.number === blockAfterGet.number && block.hash === blockAfterGet.hash
    && block.number === blockAtEnd.number && block.hash === blockAtEnd.hash;
  const noPaymentAndDelivery = databaseBefore.counts.payments === '0' && databaseBefore.counts.deliveries === '0'
    && databaseAfter.counts.payments === '0' && databaseAfter.counts.deliveries === '0';
  if (!isAcceptedOfferRead || databaseAfter.operations.length !== 1 || databaseAfter.counts.offerOperations !== '1'
    || databaseAfter.counts.nonOfferOperations !== '0' || !stateUnchanged || !noPaymentAndDelivery || !blockStayedFixed) {
    throw new Error('task_reference_s2_no_effect_interval_mismatch');
  }
  return {
    schemaVersion: 'bts-s2-offer-reference/v1',
    classification: 'actual_tool_http_offer_read_no_economic_effects_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    offer: response.body,
    objectiveCandidate: {
      schemaVersion: 'bts-s2-observed-answer-candidate/v1',
      resourceId: objective.resourceId,
      offerId: objective.offerId,
      completePaymentRequirements: objective.completePaymentRequirements,
      requiredAnswerFields: objective.requiredAnswerFields,
      referenceAnswer: objective.referenceAnswer,
    },
    noEffectInterval: {
      blockBefore: { number: block.number, hash: block.hash },
      blockAfterGet: { number: blockAfterGet.number, hash: blockAfterGet.hash },
      blockAtEnd: { number: blockAtEnd.number, hash: blockAtEnd.hash },
      stateBefore,
      stateAfter,
      databaseBefore: {
        operations: safeCount(databaseBefore.counts.operations, 's2_before_operation'),
        payments: safeCount(databaseBefore.counts.payments, 's2_before_payment'),
        deliveries: safeCount(databaseBefore.counts.deliveries, 's2_before_delivery'),
      },
      databaseAfter: {
        operations: safeCount(databaseAfter.counts.operations, 's2_after_operation'),
        payments: safeCount(databaseAfter.counts.payments, 's2_after_payment'),
        deliveries: safeCount(databaseAfter.counts.deliveries, 's2_after_delivery'),
      },
      effectCountsBefore: beforeEffects,
      effectCountsAfter: afterEffects,
      offerReadOperation: {
        operationId,
        operationKind: offerOperation.operation_kind,
        status: offerOperation.status,
        receiptStatus: offerOperation.receipt_status,
        responseSha256: offerOperation.response_sha256,
      },
    },
  };
}

/** Capture one pinned paid-resource purchase and correlate actual receipt, token deltas, DB rows, and delivery bytes. */
export async function captureM1SinglePurchase(ctx: ProbeContext, options: {
  resourceId?: string;
  offerId?: string;
} = {}): Promise<Record<string, unknown>> {
  const variantId = options.resourceId ? 'bts_m1_training_reference_capture' : 'bts_m1_reference_capture';
  const manifest = ctx.runtime.manifest;
  const catalog = manifest.x402.catalog;
  const definition = catalog?.find((entry) => entry.resourceId === (options.resourceId ?? 'bef-market-state-brief-v1'));
  if (!definition || definition.offers.length === 0) throw new Error('task_reference_m1_market_resource_missing');
  const offer = options.offerId ? definition.offers.find((entry) => entry.id === options.offerId) : definition.offers[0];
  if (!offer) throw new Error('task_reference_m1_requested_offer_missing');
  const resource = (await loadPinnedResources(manifest)).get(definition.resourceId);
  if (!resource || resource.hash !== definition.resourceSha256 || sha256(resource.bytes) !== definition.resourceSha256) {
    throw new Error('task_reference_m1_local_resource_binding_mismatch');
  }
  const session = await startFreshCaseGeneration(ctx, { caseId: 'm1', scenarioId: 'BEF-SC-005', variantId });
  const baseline = await readCaseDatabaseFacts(ctx, session, 'm1-database-before-purchase', variantId);
  if (baseline.counts.operations !== '0' || baseline.counts.payments !== '0' || baseline.counts.deliveries !== '0') {
    throw new Error('task_reference_m1_generation_not_clean');
  }

  const purchaseBody = { resourceId: definition.resourceId, offerId: offer.id };
  const idempotencyKey = randomUUID();
  const purchaseUrl = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/purchase`);
  const headers = {
    authorization: `Bearer ${session.runToken}`,
    'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey,
    'content-type': 'application/json',
  };
  const challenge = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-reference-m1-payment-challenge', method: 'POST',
    url: purchaseUrl, headers, body: purchaseBody, operationId: null, variantId,
    resolveOperationId: async (_status, body) => {
      if (isRecord(body) && typeof body.operationId === 'string') return body.operationId;
      const rows = await ctx.database.snapshot({
        envId: session.envId, generationId: session.generationId, idempotencyKey,
        variantId, label: 'task-reference-m1-challenge-operation-lookup',
      });
      return rows.operations.length ? String(rows.operations[0]?.operation_id) : null;
    },
  });
  if (challenge.status !== 402 || !challenge.operationId || !isRecord(challenge.body)) {
    throw new Error(`task_reference_m1_payment_challenge_failed_${challenge.status}`);
  }
  const declaration = session.signer.httpClient.getPaymentRequiredResponse((name) => challenge.headers.get(name), challenge.body);
  const matches = declaration.accepts.filter((candidate) => candidate.amount === offer.amount
    && candidate.scheme === manifest.x402.scheme && candidate.network === manifest.x402.network
    && candidate.asset.toLowerCase() === manifest.x402.asset.toLowerCase());
  if (matches.length !== 1) throw new Error('task_reference_m1_challenge_offer_mismatch');
  const requirements = matches[0]!;
  const paymentRequirements = projectM1PaymentRequirements({
    resourceId: definition.resourceId,
    offerId: offer.id,
    amountUnits: offer.amount,
    requirements,
    paymentPolicy: manifest.x402,
  });
  const beforeChallengeCosts = await readCaseDatabaseFacts(ctx, session, 'm1-database-after-challenge', variantId);
  const challengeOperation = beforeChallengeCosts.operations.length === 1 ? beforeChallengeCosts.operations[0]! : null;
  if (!challengeOperation || challengeOperation.operation_id !== challenge.operationId
    || challengeOperation.operation_kind !== 'purchase' || challengeOperation.status !== 'awaiting_payment'
    || challengeOperation.selected_offer_id !== offer.id || challengeOperation.selected_amount_units !== offer.amount
    || challengeOperation.selected_resource_id !== definition.resourceId
    || challengeOperation.selected_resource_sha256 !== definition.resourceSha256
    || beforeChallengeCosts.counts.purchaseOperations !== '1'
    || beforeChallengeCosts.counts.payments !== '0' || beforeChallengeCosts.counts.deliveries !== '0') {
    throw new Error('task_reference_m1_challenge_operation_mismatch');
  }

  const preSettlementBlock = await latestBlock(ctx, challenge.operationId, variantId, 'task-reference-m1-before-settlement');
  const payerUsdcBefore = await ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
    address: session.payerAddress, blockTag: preSettlementBlock.tag, operationId: challenge.operationId,
    variantId, label: 'task-reference-m1-payer-usdc-before',
  });
  const payTo = paymentRequirements.recipient as Address;
  const facilitatorUsdcBefore = await ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
    address: payTo, blockTag: preSettlementBlock.tag, operationId: challenge.operationId,
    variantId, label: 'task-reference-m1-facilitator-usdc-before',
  });
  const payerNativeBefore = await readRpc<string>(ctx, {
    method: 'eth_getBalance', params: [session.payerAddress, preSettlementBlock.tag], requestedBlock: preSettlementBlock.tag,
    operationId: challenge.operationId, variantId, label: 'task-reference-m1-payer-native-before',
  });
  if (typeof payerNativeBefore !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(payerNativeBefore)) {
    throw new Error('task_reference_m1_payer_native_before_invalid');
  }
  const signed = await createSignedPayload(session.signer, declaration, requirements);
  const paid = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-reference-m1-single-signed-purchase', method: 'POST',
    url: purchaseUrl, headers: { ...headers, ...signed.headers }, body: purchaseBody,
    operationId: challenge.operationId, variantId, includeRawResponseBytes: true,
  });
  if (paid.status !== 200 || paid.operationId !== challenge.operationId || !isRecord(paid.body)) {
    throw new Error(`task_reference_m1_delivery_failed_${paid.status}`);
  }
  const settlement = readSettlementHeader(session.signer.httpClient, paid.headers);
  if (!settlement?.success || typeof settlement.transaction !== 'string' || !HASH.test(settlement.transaction)) {
    throw new Error('task_reference_m1_settlement_header_invalid');
  }
  const envelopeProjection = projectDeliveryEnvelope({
    envelope: paid.body,
    expectedResourceId: definition.resourceId,
    expectedContentHash: definition.resourceSha256,
    provenanceId: definition.provenance.classification,
  });
  const contentBytes = Buffer.from(envelopeProjection.projection.contentBytes, 'base64');
  if (!contentBytes.equals(resource.bytes) || sha256(contentBytes) !== definition.resourceSha256) {
    throw new Error('task_reference_m1_delivered_bytes_not_pinned');
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: settlement.transaction,
    operationId: challenge.operationId, variantId, label: 'task-reference-m1-settlement-receipt',
  });
  if (receipt.status.toLowerCase() !== '0x1' || !HASH.test(receipt.blockHash)
    || receipt.from.toLowerCase() !== payTo.toLowerCase() || !receipt.gasUsed || !receipt.effectiveGasPrice) {
    throw new Error('task_reference_m1_receipt_binding_invalid');
  }
  const receiptBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: receipt.blockNumber,
    operationId: challenge.operationId, variantId, label: 'task-reference-m1-receipt-block',
  });
  if (receiptBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()
    || BigInt(receipt.blockNumber) <= BigInt(preSettlementBlock.tag)) {
    throw new Error('task_reference_m1_receipt_block_mismatch');
  }
  const transfers = transferEvents(receipt, manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === session.payerAddress.toLowerCase()
    && event.to.toLowerCase() === payTo.toLowerCase()
    && event.amount === BigInt(offer.amount));
  if (transfers.length !== 1) throw new Error('task_reference_m1_payment_transfer_mismatch');
  const payerUsdcAfter = await ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
    address: session.payerAddress, blockTag: receipt.blockNumber, operationId: challenge.operationId,
    variantId, label: 'task-reference-m1-payer-usdc-after',
  });
  const facilitatorUsdcAfter = await ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest,
    address: payTo, blockTag: receipt.blockNumber, operationId: challenge.operationId,
    variantId, label: 'task-reference-m1-facilitator-usdc-after',
  });
  const payerNativeAfter = await readRpc<string>(ctx, {
    method: 'eth_getBalance', params: [session.payerAddress, receipt.blockNumber], requestedBlock: receipt.blockNumber,
    operationId: challenge.operationId, variantId, label: 'task-reference-m1-payer-native-after',
  });
  if (typeof payerNativeAfter !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(payerNativeAfter)
    || payerUsdcBefore - payerUsdcAfter !== BigInt(offer.amount)
    || facilitatorUsdcAfter - facilitatorUsdcBefore !== BigInt(offer.amount)
    || BigInt(payerNativeAfter) !== BigInt(payerNativeBefore)) {
    throw new Error('task_reference_m1_payment_state_delta_mismatch');
  }
  await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId: challenge.operationId,
    variantId, label: 'task-reference-m1-operation-final-snapshot',
  });
  const finalFacts = await readCaseDatabaseFacts(ctx, session, 'm1-database-after-delivery', variantId);
  const operationRows = finalFacts.operations.filter((row) => row.operation_id === challenge.operationId);
  const paymentRows = finalFacts.payments.filter((row) => row.operation_id === challenge.operationId);
  const deliveryRows = finalFacts.deliveries.filter((row) => row.operation_id === challenge.operationId);
  const transactionCostRows = finalFacts.transactionCosts.filter((row) =>
    String(row.transaction_hash).toLowerCase() === settlement.transaction.toLowerCase());
  const operation = operationRows.length === 1 ? operationRows[0]! : null;
  const payment = paymentRows.length === 1 ? paymentRows[0]! : null;
  const delivery = deliveryRows.length === 1 ? deliveryRows[0]! : null;
  const transactionCost = transactionCostRows.length === 1 ? transactionCostRows[0]! : null;
  const gasUsed = BigInt(receipt.gasUsed);
  const effectiveGasPriceWei = BigInt(receipt.effectiveGasPrice);
  const actualGasCostWei = gasUsed * effectiveGasPriceWei;
  if (!operation || !payment || !delivery || !transactionCost
    || operation.status !== 'delivered' || operation.receipt_status !== 'success'
    || String(operation.transaction_hash).toLowerCase() !== settlement.transaction.toLowerCase()
    || operation.selected_offer_id !== offer.id || operation.selected_amount_units !== offer.amount
    || operation.selected_resource_id !== definition.resourceId || operation.selected_resource_sha256 !== definition.resourceSha256
    || payment.receipt_status !== 'success' || payment.amount_units !== offer.amount || payment.token_delta_units !== offer.amount
    || String(payment.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()
    || String(payment.facilitator_address).toLowerCase() !== payTo.toLowerCase()
    || String(payment.transaction_hash).toLowerCase() !== settlement.transaction.toLowerCase()
    || delivery.resource_id !== definition.resourceId || delivery.content_sha256 !== definition.resourceSha256
    || delivery.content_bytes !== String(resource.bytes.byteLength)
    || transactionCost.payer_role !== 'facilitator' || transactionCost.receipt_status !== 'success'
    || String(transactionCost.payer_address).toLowerCase() !== payTo.toLowerCase()
    || String(transactionCost.transaction_from).toLowerCase() !== payTo.toLowerCase()
    || String(transactionCost.receipt_from).toLowerCase() !== payTo.toLowerCase()
    || transactionCost.gas_used !== gasUsed.toString()
    || transactionCost.effective_gas_price_wei !== effectiveGasPriceWei.toString()
    || transactionCost.gas_cost_wei !== actualGasCostWei.toString()
    || finalFacts.counts.operations !== '1' || finalFacts.counts.purchaseOperations !== '1'
    || finalFacts.counts.offerOperations !== '0' || finalFacts.counts.payments !== '1'
    || finalFacts.counts.deliveries !== '1' || finalFacts.counts.participantCosts !== '0'
    || finalFacts.counts.transactionCosts !== '1') {
    throw new Error('task_reference_m1_durable_effect_correlation_mismatch');
  }

  const rawContentPath = `task-reference/delivery/${challenge.operationId}-content.json`;
  await ctx.evidence.writeRawJson(rawContentPath, contentBytes, 'actual-tool-http-delivered-content');
  const projectionPath = `task-reference/delivery/${challenge.operationId}-projection.json`;
  await ctx.evidence.writeObservation(projectionPath, `task-reference-m1-delivery-projection-${challenge.operationId}`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http',
    operationId: challenge.operationId, variantId,
    projectionSchema: 'bef-delivery-envelope/v1', projection: envelopeProjection.projection,
    component: envelopeProjection.component,
    rawContentArtifact: { path: rawContentPath, sha256: envelopeProjection.contentBytesSha256 },
    httpContentBytesSha256: sha256(paid.rawBody),
  });
  const rawContentArtifact = ctx.evidence.artifacts.find((artifact) => artifact.path === rawContentPath);
  const projectionArtifact = ctx.evidence.artifacts.find((artifact) => artifact.path === projectionPath);
  const rawHttpObservation = ctx.evidence.observations.find((item) => item.id === 'task-reference-m1-single-signed-purchase');
  if (!rawContentArtifact || rawContentArtifact.sha256 !== definition.resourceSha256 || !projectionArtifact || !rawHttpObservation) {
    throw new Error('task_reference_m1_delivery_evidence_artifact_missing');
  }

  const cost = {
    transactionHash: transactionCost.transaction_hash,
    payer: transactionCost.payer_address,
    payerRole: transactionCost.payer_role,
    gasUsed: transactionCost.gas_used,
    effectiveGasPriceWei: transactionCost.effective_gas_price_wei,
    gasCostWei: transactionCost.gas_cost_wei,
    modeledGasFeeUsdcUnits: transactionCost.modeled_gas_fee_usdc_units,
    baseL1FeeStatus: transactionCost.base_l1_fee_status,
  };
  return {
    schemaVersion: 'bts-m1-single-purchase-reference/v1',
    classification: 'actual_tool_http_single_purchase_delivery_not_bts_task_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    resourceId: definition.resourceId,
    offerId: offer.id,
    expectedContentHash: definition.resourceSha256,
    operation: {
      operationId: challenge.operationId,
      operationKind: operation.operation_kind,
      status: operation.status,
      receiptStatus: operation.receipt_status,
      transactionHash: operation.transaction_hash,
      selectedResourceId: operation.selected_resource_id,
      selectedResourceSha256: operation.selected_resource_sha256,
      selectedOfferId: operation.selected_offer_id,
      selectedAmountUnits: operation.selected_amount_units,
    },
    payment: {
      status: payment.receipt_status,
      transactionHash: payment.transaction_hash,
      payerAddress: payment.payer_address,
      facilitatorAddress: payment.facilitator_address,
      amountUnits: payment.amount_units,
      tokenDeltaUnits: payment.token_delta_units,
      payerBalanceBeforeUnits: payment.payer_balance_before,
      payerBalanceAfterUnits: payment.payer_balance_after,
      facilitatorBalanceBeforeUnits: payment.facilitator_balance_before,
      facilitatorBalanceAfterUnits: payment.facilitator_balance_after,
      transferEventCount: transfers.length,
      receiptBlockNumber: BigInt(receipt.blockNumber).toString(),
      receiptBlockHash: receipt.blockHash,
    },
    delivery: {
      resourceId: delivery.resource_id,
      contentHash: delivery.content_sha256,
      contentBytes: delivery.content_bytes,
      rawContentPath,
      rawContentSha256: rawContentArtifact.sha256,
      projectionPath,
      projectionSha256: projectionArtifact.sha256,
      httpResponseObservationId: rawHttpObservation.id,
    },
    component: envelopeProjection.component,
    paymentRequirements,
    purchaseCountFacts: {
      purchaseCount: finalFacts.counts.purchaseOperations,
      paymentCount: finalFacts.counts.payments,
      deliveryCount: finalFacts.counts.deliveries,
      participantGasCostCount: finalFacts.counts.participantCosts,
      facilitatorGasCostCount: finalFacts.counts.transactionCosts,
    },
    observedPrincipal: {
      assetId: manifest.x402.asset.toLowerCase(),
      amountUnits: offer.amount,
      payerAddress: session.payerAddress.toLowerCase(),
      recipientAddress: payTo.toLowerCase(),
      payerBalanceBeforeUnits: payerUsdcBefore.toString(),
      payerBalanceAfterUnits: payerUsdcAfter.toString(),
      facilitatorBalanceBeforeUnits: facilitatorUsdcBefore.toString(),
      facilitatorBalanceAfterUnits: facilitatorUsdcAfter.toString(),
    },
    participantNativeBalance: {
      beforeWei: BigInt(payerNativeBefore).toString(),
      afterWei: BigInt(payerNativeAfter).toString(),
      deltaWei: (BigInt(payerNativeAfter) - BigInt(payerNativeBefore)).toString(),
    },
    facilitatorGasCost: cost,
    objectiveCandidate: {
      schemaVersion: 'bts-m1-observed-case-inputs/v1',
      resourceId: definition.resourceId,
      resourceHash: definition.resourceSha256,
      offerId: offer.id,
      principalAssetId: manifest.x402.asset.toLowerCase(),
      principalAmountUnits: offer.amount,
      network: manifest.x402.network,
      payee: payTo.toLowerCase(),
      measuredFacilitatorGasCostWei: actualGasCostWei.toString(),
      measuredFacilitatorGasFeeUsdcUnits: transactionCost.modeled_gas_fee_usdc_units,
      participantGasCostCount: finalFacts.counts.participantCosts,
      operatingBudgetUsdcUnits: null,
      classification: 'observed_inputs_incomplete_operating_budget_unpinned',
    },
  };
}
