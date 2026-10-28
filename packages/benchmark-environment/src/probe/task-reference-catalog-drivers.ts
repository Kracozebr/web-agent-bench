/** Actual public-catalog reference captures for S3 and M2. */
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import pg from 'pg';
import { encodeFunctionData, parseAbi, type Address } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import { loadPinnedResources } from '../resource.js';
import { apiPath, newParticipantId } from './environment.js';
import { sanitizeValue, sha256Bytes } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import { createEphemeralSigner, createSignedPayload, readSettlementHeader } from './x402.js';
import { transferEvents } from './rpc.js';
import { projectDeliveryEnvelope, type DataComponentProjection } from './task-reference-cases.js';
import {
  minimumM2Offer,
  projectM2CatalogObjective,
  projectPinnedPublicCatalog,
  projectS3CatalogObjective,
  type CatalogObjectiveCandidate,
  type CatalogOfferObservation,
  type PublicCatalogProjection,
} from './task-reference-catalog-objectives.js';

const { Pool } = pg;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const TOKEN_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
]);

type DbFacts = {
  counts: {
    operations: string; offerOperations: string; purchaseOperations: string; nonOfferOperations: string;
    payments: string; deliveries: string; denials: string; x402Observations: string;
    selectedExecutions: string; selectedExecutionEvents: string; transactionCosts: string; participantCosts: string;
  };
  operations: Array<Record<string, unknown>>;
  payments: Array<Record<string, unknown>>;
  deliveries: Array<Record<string, unknown>>;
  transactionCosts: Array<Record<string, unknown>>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function needString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_reference_catalog_${label}_missing`);
  return value;
}

function sha256(value: Uint8Array | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeCount(value: string, label: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`task_reference_catalog_${label}_count_invalid`);
  }
  return Number(value);
}

async function readRpc<T>(ctx: ProbeContext, input: {
  method: string; params: unknown[]; requestedBlock?: string; operationId: string | null; variantId: string; label: string;
}): Promise<T> {
  const { result } = await ctx.rpc.call<T>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: ctx.env.envId,
    method: input.method, params: input.params,
    ...(input.requestedBlock === undefined ? {} : { requestedBlock: input.requestedBlock }),
    operationId: input.operationId, variantId: input.variantId, label: input.label,
  });
  return result;
}

async function latestBlock(ctx: ProbeContext, operationId: string | null, variantId: string, label: string): Promise<{ tag: string; number: string; hash: string }> {
  const tag = await readRpc<string>(ctx, { method: 'eth_blockNumber', params: [], operationId, variantId, label: `${label}-height` });
  if (typeof tag !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(tag)) throw new Error('task_reference_catalog_block_height_invalid');
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: tag,
    operationId, variantId, label: `${label}-identity`,
  });
  return { tag, number: BigInt(tag).toString(), hash: block.hash.toLowerCase() };
}

async function tokenBalance(ctx: ProbeContext, address: string, blockTag: string, operationId: string | null, variantId: string, label: string): Promise<bigint> {
  if (!ADDRESS.test(address)) throw new Error('task_reference_catalog_token_account_invalid');
  return ctx.rpc.tokenBalance({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', manifest: ctx.runtime.manifest,
    address: address as Address, blockTag, operationId, variantId, label,
  });
}

async function nativeBalance(ctx: ProbeContext, address: string, blockTag: string, operationId: string | null, variantId: string, label: string): Promise<bigint> {
  if (!ADDRESS.test(address)) throw new Error('task_reference_catalog_native_account_invalid');
  const value = await readRpc<string>(ctx, {
    method: 'eth_getBalance', params: [address, blockTag], requestedBlock: blockTag, operationId, variantId, label,
  });
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) {
    throw new Error('task_reference_catalog_native_balance_invalid');
  }
  return BigInt(value);
}

async function readStateAt(ctx: ProbeContext, session: GenerationSession, block: { tag: string; number: string; hash: string }, operationId: string | null, variantId: string, label: string): Promise<Record<string, string>> {
  const manifest = ctx.runtime.manifest;
  const callToken = async (token: string, functionName: 'balanceOf' | 'allowance', args: readonly Address[], readLabel: string) => {
    const data = functionName === 'balanceOf'
      ? encodeFunctionData({ abi: TOKEN_ABI, functionName, args: [args[0]!] })
      : encodeFunctionData({ abi: TOKEN_ABI, functionName, args: [args[0]!, args[1]!] });
    const { result } = await ctx.rpc.call<string>({
      url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: ctx.env.envId,
      method: 'eth_call', params: [{ to: token as Address, data }, block.tag], requestedBlock: block.tag,
      operationId, variantId, label: readLabel,
    });
    if (typeof result !== 'string' || !/^0x[0-9a-f]{64}$/i.test(result)) throw new Error('task_reference_catalog_token_word_invalid');
    return BigInt(result);
  };
  const [native, usdc, weth, usdcAllowance, wethAllowance] = await Promise.all([
    nativeBalance(ctx, session.payerAddress, block.tag, operationId, variantId, `${label}-native`),
    tokenBalance(ctx, session.payerAddress, block.tag, operationId, variantId, `${label}-usdc`),
    callToken(manifest.contracts.weth.address, 'balanceOf', [session.payerAddress], `${label}-weth`),
    callToken(manifest.contracts.usdc.address, 'allowance', [session.payerAddress, manifest.contracts.swapRouter02.address as Address], `${label}-usdc-router-allowance`),
    callToken(manifest.contracts.weth.address, 'allowance', [session.payerAddress, manifest.contracts.swapRouter02.address as Address], `${label}-weth-router-allowance`),
  ]);
  return {
    blockNumber: block.number,
    blockHash: block.hash,
    payerAddress: session.payerAddress.toLowerCase(),
    payerNativeEthWei: native.toString(),
    payerUsdcUnits: usdc.toString(),
    payerWethUnits: weth.toString(),
    usdcRouterAllowanceUnits: usdcAllowance.toString(),
    wethRouterAllowanceUnits: wethAllowance.toString(),
  };
}

async function startFreshGeneration(ctx: ProbeContext, caseId: 's3' | 'm2', scenarioId: string, variantId: string): Promise<GenerationSession> {
  const priorGenerationId = ctx.primaryGeneration?.generationId ?? null;
  const resetRoute = ctx.capability.reset?.route?.replace(/^POST\s+/i, '').replace('{envId}', ctx.env.envId);
  if (!ctx.capability.reset?.supported || !resetRoute || !resetRoute.startsWith('/internal/admin/environments/')) {
    throw new Error(`task_reference_${caseId}_reset_route_unavailable`);
  }
  const reset = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-reference-${caseId}-reset`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, resetRoute), headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: {}, operationId: null, variantId,
  });
  if (reset.status < 200 || reset.status >= 300) throw new Error(`task_reference_${caseId}_reset_failed_${reset.status}`);
  const chainId = await readRpc<string>(ctx, { method: 'eth_chainId', params: [], operationId: null, variantId, label: `task-reference-${caseId}-chain-id` });
  if (typeof chainId !== 'string' || BigInt(chainId) !== BigInt(ctx.runtime.manifest.local.chainId)) {
    throw new Error(`task_reference_${caseId}_chain_id_mismatch`);
  }
  const forkBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: ctx.runtime.manifest.local.forkBlock,
    operationId: null, variantId, label: `task-reference-${caseId}-fork-block`,
  });
  if (forkBlock.hash.toLowerCase() !== ctx.runtime.manifest.source.blockHash.toLowerCase()) {
    throw new Error(`task_reference_${caseId}_fork_identity_mismatch`);
  }
  const signer = createEphemeralSigner();
  ctx.secretValues.push(signer.privateKey);
  const participantId = newParticipantId(scenarioId);
  const created = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `task-reference-${caseId}-generation`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${ctx.env.envId}/generations`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' },
    body: { participantId, payerAddress: signer.payerAddress, payerPrivateKey: signer.privateKey, resourceVariant: 'canonical' },
    operationId: null, variantId,
  });
  const body = isRecord(created.body) ? created.body : null;
  if (created.status < 200 || created.status >= 300 || !body) throw new Error(`task_reference_${caseId}_generation_failed_${created.status}`);
  const session: GenerationSession = {
    envId: needString(body.envId, 'env_id'), generationId: needString(body.generationId, 'generation_id'),
    participantId, payerAddress: signer.payerAddress,
    runToken: needString(body.runToken ?? (isRecord(body.participant) ? body.participant.runToken : undefined), 'run_token'), signer,
  };
  if (session.envId !== ctx.env.envId || String(body.payerAddress).toLowerCase() !== signer.payerAddress.toLowerCase()
    || priorGenerationId === session.generationId) throw new Error(`task_reference_${caseId}_generation_identity_mismatch`);
  ctx.secretValues.push(session.runToken);
  ctx.primaryGeneration = { envId: session.envId, generationId: session.generationId, participantId, payerAddress: signer.payerAddress };
  ctx.primarySession = session;
  await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId, variantId, label: `task-reference-${caseId}-generation` });
  return session;
}

async function databaseFacts(ctx: ProbeContext, session: GenerationSession, label: string, variantId: string): Promise<DbFacts> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000, query_timeout: 8_000, application_name: `web-agent-bench-bef-reference-${label}`,
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operations, payments, deliveries, counts, costs] = await Promise.all([
      client.query<{ role_name: string }>('SELECT current_user AS role_name'),
      client.query<{ transaction_read_only: string }>('SHOW transaction_read_only'),
      client.query(`SELECT operation_id::text,operation_kind,status,receipt_status,transaction_hash,response_sha256,
                           selected_offer_id,selected_amount_units::text,selected_resource_id,selected_resource_sha256
                      FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY started_at,operation_id`,
        [session.envId, session.generationId]),
      client.query(`SELECT operation_id::text,payer_address,network,asset_address,amount_units::text,facilitator_address,
                           transaction_hash,receipt_status,token_delta_units::text,payer_balance_before::text,payer_balance_after::text,
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
      client.query(`SELECT transaction_hash,payer_address,payer_role,receipt_status,transaction_from,receipt_from,
                           gas_used::text,effective_gas_price_wei::text,gas_cost_wei::text,modeled_gas_fee_usdc_units::text,
                           receipt_block_number::text,receipt_block_hash,base_l1_fee_status
                      FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY transaction_hash`,
        [session.envId, session.generationId]),
    ]);
    if (role.rows[0]?.role_name !== ctx.database.databaseRole || mode.rows[0]?.transaction_read_only !== 'on') {
      throw new Error(`task_reference_${label}_database_not_readonly`);
    }
    const countRow = counts.rows[0];
    if (!countRow) throw new Error(`task_reference_${label}_database_counts_missing`);
    const facts: DbFacts = {
      counts: {
        operations: countRow.operations, offerOperations: countRow.offer_operations, purchaseOperations: countRow.purchase_operations,
        nonOfferOperations: countRow.non_offer_operations, payments: countRow.payments, deliveries: countRow.deliveries,
        denials: countRow.denials, x402Observations: countRow.x402_observations, selectedExecutions: countRow.selected_executions,
        selectedExecutionEvents: countRow.selected_execution_events, transactionCosts: countRow.transaction_costs,
        participantCosts: countRow.participant_costs,
      },
      operations: operations.rows as Array<Record<string, unknown>>,
      payments: payments.rows as Array<Record<string, unknown>>,
      deliveries: deliveries.rows as Array<Record<string, unknown>>,
      transactionCosts: costs.rows as Array<Record<string, unknown>>,
    };
    await client.query('COMMIT');
    await ctx.evidence.writeObservation(`db/task-reference/${label}.json`, `task-reference-${label}`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: null, variantId,
      envId: session.envId, generationId: session.generationId, readOnly: true,
      databaseRole: ctx.database.databaseRole, transactionReadOnly: 'on',
      queryName: 'task-reference-catalog-operation-payment-delivery-cost-census', rows: sanitizeValue(facts),
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

function effectCounts(counts: DbFacts['counts']): Record<string, string> {
  return {
    operations: counts.operations, payments: counts.payments, deliveries: counts.deliveries,
    denials: counts.denials, x402Observations: counts.x402Observations,
    selectedExecutions: counts.selectedExecutions, selectedExecutionEvents: counts.selectedExecutionEvents,
    transactionCosts: counts.transactionCosts, participantCosts: counts.participantCosts,
  };
}

function assertNoEffects(counts: Record<string, string>, label: string): void {
  if (Object.values(counts).some((value) => value !== '0')) throw new Error(`task_reference_${label}_unexpected_effect`);
}

async function getPublicCatalog(ctx: ProbeContext, session: GenerationSession, variantId: string, observationId: string): Promise<{ response: unknown; projection: PublicCatalogProjection }> {
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId, method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/catalog`),
    headers: { authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': randomUUID(), 'content-type': 'application/json' },
    body: undefined, operationId: null, variantId,
  });
  if (response.status !== 200 || !isRecord(response.body)) throw new Error(`task_reference_catalog_http_failed_${response.status}`);
  return { response: response.body, projection: projectPinnedPublicCatalog({ response: response.body, manifest: ctx.runtime.manifest }) };
}

async function previouslyObservedComponents(ctx: ProbeContext): Promise<DataComponentProjection[]> {
  const result: DataComponentProjection[] = [];
  for (const artifact of ctx.evidence.artifacts.filter((item) => item.path.startsWith('task-reference/delivery/') && item.path.endsWith('-projection.json'))) {
    const path = resolve(ctx.evidence.directory, artifact.path);
    const rel = relative(ctx.evidence.directory, path);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error('task_reference_catalog_projection_path_invalid');
    const bytes = await readFile(path);
    if (sha256Bytes(bytes) !== artifact.sha256) throw new Error('task_reference_catalog_component_artifact_hash_mismatch');
    const observation = JSON.parse(bytes.toString('utf8')) as unknown;
    if (!isRecord(observation) || observation.projectionSchema !== 'bef-delivery-envelope/v1' || !isRecord(observation.component)) continue;
    const component = observation.component as unknown as DataComponentProjection;
    if (typeof component.resourceId === 'string' && component.validator?.payloadSchemaVersion === 'bef-delivery-envelope/v1') result.push(component);
  }
  return result;
}

function candidateDataType(catalog: PublicCatalogProjection, dataType: string): CatalogOfferObservation[] {
  const offers = catalog.offers.filter((offer) => offer.dataType === dataType);
  if (offers.length < 2 || offers.some((offer) => !offer.dataType)) throw new Error('task_reference_catalog_data_type_scope_unavailable');
  return offers;
}

function parseCost(row: Record<string, unknown>, tx: string, facilitator: string, manifest: RuntimeManifest): Record<string, string> {
  const integer = (value: unknown, name: string) => {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`task_reference_m2_${name}_invalid`);
    return BigInt(value).toString();
  };
  const transactionHash = needString(row.transaction_hash, 'm2_cost_tx');
  const payerAddress = needString(row.payer_address, 'm2_cost_payer').toLowerCase();
  const gasUsed = integer(row.gas_used, 'gas_used');
  const effectiveGasPriceWei = integer(row.effective_gas_price_wei, 'effective_gas_price');
  const gasCostWei = integer(row.gas_cost_wei, 'gas_cost');
  const modeledFee = integer(row.modeled_gas_fee_usdc_units, 'modeled_gas_fee');
  const rateNumerator = BigInt(manifest.feePolicy.ethUsdcRateNumerator);
  const rateDenominator = BigInt(manifest.feePolicy.ethUsdcRateDenominator);
  if (rateDenominator <= 0n) throw new Error('task_reference_m2_fee_denominator_invalid');
  const expectedModeledFee = ((BigInt(gasCostWei) * rateNumerator) / rateDenominator).toString();
  if (transactionHash.toLowerCase() !== tx.toLowerCase() || row.payer_role !== 'facilitator'
    || payerAddress !== facilitator.toLowerCase() || row.receipt_status !== 'success'
    || needString(row.transaction_from, 'm2_cost_sender').toLowerCase() !== facilitator.toLowerCase()
    || needString(row.receipt_from, 'm2_cost_receipt_sender').toLowerCase() !== facilitator.toLowerCase()
    || BigInt(gasUsed) * BigInt(effectiveGasPriceWei) !== BigInt(gasCostWei)
    || modeledFee !== expectedModeledFee
    || row.base_l1_fee_status !== 'unmodelled') {
    throw new Error('task_reference_m2_facilitator_cost_mismatch');
  }
  return { transactionHash: transactionHash.toLowerCase(), payer: payerAddress, payerRole: 'facilitator', gasUsed,
    effectiveGasPriceWei, gasCostWei, modeledGasFeeUsdcUnits: modeledFee,
    receiptBlockNumber: integer(row.receipt_block_number, 'cost_block_number'),
    receiptBlockHash: needString(row.receipt_block_hash, 'cost_block_hash').toLowerCase() };
}

function ensureBlockHash(value: unknown, label: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) throw new Error(`task_reference_m2_${label}_hash_invalid`);
  return value.toLowerCase();
}

/**
 * AICODE-NOTE: S3 uses public GET /catalog only. The offer answer here is a
 * review candidate; owner finish/cutoff evidence remains a separate boundary.
 */
export async function captureS3ReadonlyCatalog(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const caseId = 's3';
  const variantId = 'bts_s3_reference_capture';
  const session = await startFreshGeneration(ctx, caseId, 'BEF-SC-004', variantId);
  const blockBefore = await latestBlock(ctx, null, variantId, 'task-reference-s3-before');
  const stateBefore = await readStateAt(ctx, session, blockBefore, null, variantId, 'task-reference-s3-state-before');
  const databaseBefore = await databaseFacts(ctx, session, 's3-database-before', variantId);
  if (databaseBefore.counts.operations !== '0') throw new Error('task_reference_s3_generation_not_clean');
  assertNoEffects(effectCounts(databaseBefore.counts), 's3_before');

  const catalogRead = await getPublicCatalog(ctx, session, variantId, 'task-reference-s3-public-catalog-read');
  const blockAfterGet = await latestBlock(ctx, null, variantId, 'task-reference-s3-after-catalog');
  const stateAfter = await readStateAt(ctx, session, blockAfterGet, null, variantId, 'task-reference-s3-state-after');
  const databaseAfter = await databaseFacts(ctx, session, 's3-database-after', variantId);
  const blockAtEnd = await latestBlock(ctx, null, variantId, 'task-reference-s3-interval-end');
  const blocksStable = blockBefore.number === blockAfterGet.number && blockBefore.hash === blockAfterGet.hash
    && blockBefore.number === blockAtEnd.number && blockBefore.hash === blockAtEnd.hash;
  const stateStable = JSON.stringify(stateBefore) === JSON.stringify(stateAfter);
  const zeroEffects = Object.values(effectCounts(databaseAfter.counts)).every((value) => value === '0');
  if (!blocksStable || !stateStable || !zeroEffects || databaseAfter.operations.length !== 0) {
    throw new Error('task_reference_s3_no_effect_interval_mismatch');
  }

  const components = await previouslyObservedComponents(ctx);
  const objectiveCandidate = projectS3CatalogObjective({
    publicCatalog: catalogRead.projection,
    components,
    requiredDataType: 'market-state-brief',
    referenceOfferId: 'market-brief-extended',
  });
  return {
    schemaVersion: 'bts-s3-catalog-reference/v1',
    classification: 'actual_tool_http_public_catalog_read_and_derived_answer_candidate_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    catalogResponse: catalogRead.response,
    objectiveCandidate: {
      ...objectiveCandidate,
      policyReviewStatus: 'candidate_requires_release_review',
    },
    noEffectInterval: {
      blockBefore: { number: blockBefore.number, hash: blockBefore.hash },
      blockAfterGet: { number: blockAfterGet.number, hash: blockAfterGet.hash },
      blockAtEnd: { number: blockAtEnd.number, hash: blockAtEnd.hash },
      stateBefore,
      stateAfter,
      databaseBefore: { operations: safeCount(databaseBefore.counts.operations, 's3_before_operation'), payments: 0, deliveries: 0 },
      databaseAfter: { operations: safeCount(databaseAfter.counts.operations, 's3_after_operation'), payments: 0, deliveries: 0 },
      effectCountsBefore: effectCounts(databaseBefore.counts),
      effectCountsAfter: effectCounts(databaseAfter.counts),
    },
  };
}

function selectMinimumBrief(catalog: PublicCatalogProjection): { offers: CatalogOfferObservation[]; selected: CatalogOfferObservation; maximum: string } {
  const offers = candidateDataType(catalog, 'market-state-brief');
  const ids = new Set(offers.map((offer) => offer.offerId));
  if (ids.size !== offers.length) throw new Error('task_reference_m2_duplicate_offer_identity');
  const resourceIds = new Set(offers.map((offer) => offer.resourceId));
  const networks = new Set(offers.map((offer) => offer.network));
  const assets = new Set(offers.map((offer) => offer.assetId));
  const recipients = new Set(offers.map((offer) => offer.recipient.toLowerCase()));
  if (resourceIds.size !== 1 || networks.size !== 1 || assets.size !== 1 || recipients.size !== 1) {
    throw new Error('task_reference_m2_catalog_requirements_not_uniform');
  }
  const prices = new Set(offers.map((offer) => offer.advertisedTotalPriceUsdcUnits));
  if (prices.size < 2) throw new Error('task_reference_m2_prices_not_distinct');
  const min = offers.reduce((value, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) < value
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : value, BigInt(offers[0]!.advertisedTotalPriceUsdcUnits));
  const selected = offers.find((offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) === min)!;
  const max = offers.reduce((value, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) > value
    ? BigInt(offer.advertisedTotalPriceUsdcUnits) : value, 0n);
  return { offers, selected, maximum: max.toString() };
}

/**
 * AICODE-NOTE: This driver performs one local-fork x402 settlement. Keep calls
 * bound to the pinned local fork and its ephemeral generation payer.
 */
export async function captureM2MinimumPurchase(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const caseId = 'm2';
  const variantId = 'bts_m2_reference_capture';
  const manifest = ctx.runtime.manifest;
  const session = await startFreshGeneration(ctx, caseId, 'BEF-SC-006', variantId);
  const catalogRead = await getPublicCatalog(ctx, session, variantId, 'task-reference-m2-public-catalog-read');
  const choice = selectMinimumBrief(catalogRead.projection);
  const definition = manifest.x402.catalog?.find((item) => item.resourceId === choice.selected.resourceId);
  const offer = definition?.offers.find((item) => item.id === choice.selected.offerId);
  const resources = await loadPinnedResources(manifest);
  const pinnedContent = resources.get(choice.selected.resourceId);
  if (!definition || !offer || !pinnedContent || pinnedContent.hash !== definition.resourceSha256
    || sha256(pinnedContent.bytes) !== definition.resourceSha256) throw new Error('task_reference_m2_selected_resource_pin_missing');

  const baselineBlock = await latestBlock(ctx, null, variantId, 'task-reference-m2-baseline');
  const databaseBefore = await databaseFacts(ctx, session, 'm2-database-before', variantId);
  if (databaseBefore.counts.operations !== '0' || databaseBefore.counts.payments !== '0' || databaseBefore.counts.deliveries !== '0') {
    throw new Error('task_reference_m2_generation_not_clean');
  }
  const payerUsdcBefore = await tokenBalance(ctx, session.payerAddress, baselineBlock.tag, null, variantId, 'task-reference-m2-payer-usdc-before');
  const facilitatorUsdcBefore = await tokenBalance(ctx, catalogRead.projection.facilitatorAddress, baselineBlock.tag, null, variantId, 'task-reference-m2-facilitator-usdc-before');
  const payerNativeBefore = await nativeBalance(ctx, session.payerAddress, baselineBlock.tag, null, variantId, 'task-reference-m2-payer-native-before');

  const idempotencyKey = randomUUID();
  const body = { resourceId: definition.resourceId, offerId: offer.id };
  const purchaseUrl = apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/purchase`);
  const baseHeaders = { authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
    'Idempotency-Key': idempotencyKey, 'content-type': 'application/json' };
  const challenge = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-reference-m2-payment-challenge', method: 'POST',
    url: purchaseUrl, headers: baseHeaders, body, operationId: null, variantId,
    resolveOperationId: async (_status, responseBody) => {
      if (isRecord(responseBody) && typeof responseBody.operationId === 'string') return responseBody.operationId;
      const rows = await ctx.database.snapshot({
        envId: session.envId, generationId: session.generationId, idempotencyKey,
        variantId, label: 'task-reference-m2-challenge-operation-lookup',
      });
      return rows.operations.length === 1 ? String(rows.operations[0]?.operation_id) : null;
    },
  });
  if (challenge.status !== 402 || !challenge.operationId || !isRecord(challenge.body)) {
    throw new Error(`task_reference_m2_payment_challenge_failed_${challenge.status}`);
  }
  const challengeFacts = await databaseFacts(ctx, session, 'm2-database-after-challenge', variantId);
  const challengeOperation = challengeFacts.operations.length === 1 ? challengeFacts.operations[0]! : null;
  if (!challengeOperation || String(challengeOperation.operation_id) !== challenge.operationId
    || challengeOperation.operation_kind !== 'purchase' || challengeOperation.status !== 'awaiting_payment'
    || challengeOperation.selected_offer_id !== offer.id || challengeOperation.selected_amount_units !== offer.amount
    || challengeOperation.selected_resource_id !== definition.resourceId
    || challengeOperation.selected_resource_sha256 !== definition.resourceSha256
    || challengeFacts.counts.purchaseOperations !== '1'
    || challengeFacts.counts.payments !== '0' || challengeFacts.counts.deliveries !== '0') {
    throw new Error('task_reference_m2_challenge_operation_mismatch');
  }
  const declaration = session.signer.httpClient.getPaymentRequiredResponse((name) => challenge.headers.get(name), challenge.body);
  const requirements = declaration.accepts.find((candidate) => candidate.amount === offer.amount
    && candidate.scheme === manifest.x402.scheme && candidate.network === manifest.x402.network
    && candidate.asset.toLowerCase() === manifest.x402.asset.toLowerCase());
  if (!requirements || requirements.payTo.toLowerCase() !== catalogRead.projection.facilitatorAddress.toLowerCase()) {
    throw new Error('task_reference_m2_challenge_requirements_mismatch');
  }
  if (!isRecord(requirements.extra) || requirements.extra.assetTransferMethod !== manifest.x402.assetTransferMethod
    || requirements.extra.paymentFlow !== 'authorization' || requirements.extra.name !== manifest.x402.eip712Domain.name
    || requirements.extra.version !== manifest.x402.eip712Domain.version) throw new Error('task_reference_m2_challenge_auth_policy_mismatch');
  const signed = await createSignedPayload(session.signer, declaration, requirements);
  const paid = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-reference-m2-single-signed-purchase', method: 'POST',
    url: purchaseUrl, headers: { ...baseHeaders, ...signed.headers }, body,
    operationId: challenge.operationId, variantId, includeRawResponseBytes: true,
  });
  if (paid.status !== 200 || paid.operationId !== challenge.operationId || !isRecord(paid.body)) {
    throw new Error(`task_reference_m2_delivery_failed_${paid.status}`);
  }
  const settlement = readSettlementHeader(session.signer.httpClient, paid.headers);
  if (!settlement?.success || typeof settlement.transaction !== 'string' || !HASH.test(settlement.transaction)) {
    throw new Error('task_reference_m2_settlement_header_invalid');
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: settlement.transaction,
    operationId: challenge.operationId, variantId, label: 'task-reference-m2-settlement-receipt',
  });
  if (receipt.status.toLowerCase() !== '0x1' || receipt.transactionHash.toLowerCase() !== settlement.transaction.toLowerCase()
    || receipt.from.toLowerCase() !== catalogRead.projection.facilitatorAddress.toLowerCase()) {
    throw new Error('task_reference_m2_receipt_sender_or_status_mismatch');
  }
  const payer = session.payerAddress.toLowerCase();
  const payee = catalogRead.projection.facilitatorAddress.toLowerCase();
  const transfers = transferEvents(receipt, manifest.contracts.usdc.address);
  const payerTransfers = transfers.filter((event) => event.from.toLowerCase() === payer);
  if (payerTransfers.length !== 1 || payerTransfers[0]!.to.toLowerCase() !== payee
    || payerTransfers[0]!.amount !== BigInt(offer.amount)) throw new Error('task_reference_m2_receipt_transfer_mismatch');
  const payerUsdcAfter = await tokenBalance(ctx, session.payerAddress, receipt.blockNumber, challenge.operationId, variantId, 'task-reference-m2-payer-usdc-after');
  const facilitatorUsdcAfter = await tokenBalance(ctx, catalogRead.projection.facilitatorAddress, receipt.blockNumber, challenge.operationId, variantId, 'task-reference-m2-facilitator-usdc-after');
  const payerNativeAfter = await nativeBalance(ctx, session.payerAddress, receipt.blockNumber, challenge.operationId, variantId, 'task-reference-m2-payer-native-after');
  const actualPayerDelta = payerUsdcBefore - payerUsdcAfter;
  const actualFacilitatorDelta = facilitatorUsdcAfter - facilitatorUsdcBefore;
  if (actualPayerDelta !== BigInt(offer.amount) || actualFacilitatorDelta !== BigInt(offer.amount) || payerNativeAfter !== payerNativeBefore) {
    throw new Error('task_reference_m2_token_or_native_delta_mismatch');
  }
  const envelope = paid.body;
  if (envelope.resourceId !== definition.resourceId || envelope.contentType !== definition.contentType
    || envelope.contentHash !== definition.resourceSha256 || typeof envelope.contentBytes !== 'string') {
    throw new Error('task_reference_m2_delivery_envelope_manifest_mismatch');
  }
  const envelopeProjection = projectDeliveryEnvelope({
    envelope, expectedResourceId: definition.resourceId, expectedContentHash: definition.resourceSha256,
    provenanceId: definition.provenance.classification,
  });
  if (JSON.stringify(envelopeProjection.parsedContent) !== JSON.stringify(pinnedContent.parsed)) {
    throw new Error('task_reference_m2_delivered_content_pin_mismatch');
  }
  const finalFacts = await databaseFacts(ctx, session, 'm2-database-after', variantId);
  const operationRows = finalFacts.operations.filter((row) => row.operation_id === challenge.operationId);
  const paymentRows = finalFacts.payments.filter((row) => row.operation_id === challenge.operationId);
  const deliveryRows = finalFacts.deliveries.filter((row) => row.operation_id === challenge.operationId);
  const costRows = finalFacts.transactionCosts.filter((row) => String(row.transaction_hash).toLowerCase() === settlement.transaction.toLowerCase());
  const operation = operationRows.length === 1 ? operationRows[0]! : null;
  const payment = paymentRows.length === 1 ? paymentRows[0]! : null;
  const delivery = deliveryRows.length === 1 ? deliveryRows[0]! : null;
  const costRow = costRows.length === 1 ? costRows[0]! : null;
  if (!operation || operation.operation_kind !== 'purchase' || operation.status !== 'delivered' || operation.receipt_status !== 'success'
    || String(operation.transaction_hash).toLowerCase() !== settlement.transaction.toLowerCase()
    || operation.selected_offer_id !== offer.id || operation.selected_amount_units !== offer.amount
    || operation.selected_resource_id !== definition.resourceId || operation.selected_resource_sha256 !== definition.resourceSha256
    || !payment || payment.receipt_status !== 'success' || payment.amount_units !== offer.amount || payment.token_delta_units !== offer.amount
    || String(payment.payer_address).toLowerCase() !== payer || String(payment.facilitator_address).toLowerCase() !== payee
    || String(payment.transaction_hash).toLowerCase() !== settlement.transaction.toLowerCase()
    || delivery?.resource_id !== definition.resourceId || delivery.content_sha256 !== definition.resourceSha256
    || Number(delivery.content_bytes) !== pinnedContent.bytes.byteLength
    || finalFacts.counts.operations !== '1' || finalFacts.counts.purchaseOperations !== '1' || finalFacts.counts.offerOperations !== '0'
    || finalFacts.counts.payments !== '1' || finalFacts.counts.deliveries !== '1' || finalFacts.counts.transactionCosts !== '1'
    || finalFacts.counts.participantCosts !== '0' || finalFacts.counts.denials !== '0' || finalFacts.counts.selectedExecutions !== '0'
    || finalFacts.counts.selectedExecutionEvents !== '0' || !costRow) {
    throw new Error('task_reference_m2_durable_effect_correlation_mismatch');
  }
  const facilitatorGasCost = parseCost(costRow, settlement.transaction, payee, manifest);
  if (facilitatorGasCost.receiptBlockNumber !== BigInt(receipt.blockNumber).toString()
    || facilitatorGasCost.receiptBlockHash !== ensureBlockHash(receipt.blockHash, 'receipt')) {
    throw new Error('task_reference_m2_cost_receipt_identity_mismatch');
  }
  const objectiveCandidate = projectM2CatalogObjective({
    publicCatalog: catalogRead.projection,
    components: [envelopeProjection.component],
  });
  const minimum = minimumM2Offer(objectiveCandidate);
  if (minimum.offerId !== offer.id || minimum.resourceId !== definition.resourceId
    || minimum.advertisedTotalPriceUsdcUnits !== offer.amount) throw new Error('task_reference_m2_selected_offer_not_minimum');

  const rawContentPath = `task-reference/delivery/${challenge.operationId}-m2-content.json`;
  await ctx.evidence.writeRawJson(rawContentPath, Buffer.from(envelopeProjection.projection.contentBytes, 'base64'), 'actual-tool-http-delivered-content');
  const projectionPath = `task-reference/delivery/${challenge.operationId}-m2-projection.json`;
  await ctx.evidence.writeObservation(projectionPath, `task-reference-m2-delivery-projection-${challenge.operationId}`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http', operationId: challenge.operationId, variantId,
    projectionSchema: 'bef-delivery-envelope/v1', projection: envelopeProjection.projection,
    component: envelopeProjection.component,
    rawContentArtifact: { path: rawContentPath, sha256: envelopeProjection.contentBytesSha256 },
  });
  const rawContent = ctx.evidence.artifacts.find((item) => item.path === rawContentPath);
  if (!rawContent || rawContent.sha256 !== envelopeProjection.contentBytesSha256) throw new Error('task_reference_m2_raw_content_hash_mismatch');

  return {
    schemaVersion: 'bts-m2-minimum-purchase-reference/v1',
    classification: 'actual_tool_http_minimum_qualifying_purchase_and_verified_delivery_not_bts_acceptance',
    status: 'captured',
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId, payerAddress: session.payerAddress },
    catalogResponse: catalogRead.response,
    objectiveCandidate: {
      ...objectiveCandidate,
      expenseBudgetUsdcUnits: null,
      tiePolicy: 'all_minimum_advertised_total_prices_qualify',
      duplicatePurchaseIdentity: 'one_public_purchase_operation',
      policyReviewStatus: 'candidate_requires_budget_and_release_review',
    },
    selectedOffer: {
      resourceId: definition.resourceId,
      offerId: offer.id,
      dataType: definition.dataType,
      advertisedTotalPriceUsdcUnits: offer.amount,
      operationId: challenge.operationId,
      transactionHash: settlement.transaction.toLowerCase(),
    },
    operation: {
      operationId: challenge.operationId,
      operationKind: operation.operation_kind,
      status: operation.status,
      receiptStatus: operation.receipt_status,
      transactionHash: String(operation.transaction_hash).toLowerCase(),
    },
    receipt: {
      transactionHash: receipt.transactionHash.toLowerCase(),
      status: receipt.status.toLowerCase(),
      blockNumber: BigInt(receipt.blockNumber).toString(),
      blockHash: receipt.blockHash.toLowerCase(),
      from: receipt.from.toLowerCase(),
      gasUsed: facilitatorGasCost.gasUsed,
      effectiveGasPriceWei: facilitatorGasCost.effectiveGasPriceWei,
    },
    transferEffect: {
      tokenAssetId: manifest.contracts.usdc.address.toLowerCase(),
      from: payer,
      to: payee,
      amountUnits: payerTransfers[0]!.amount.toString(),
      receiptTransferCountFromPayer: payerTransfers.length,
    },
    payment: {
      status: 'settled',
      operationId: challenge.operationId,
      transactionHash: settlement.transaction.toLowerCase(),
      receiptStatus: receipt.status,
      payerAddress: payer,
      recipient: payee,
      assetId: manifest.x402.asset.toLowerCase(),
      network: manifest.x402.network,
      amountUnits: offer.amount,
      payerBalanceBeforeUnits: payerUsdcBefore.toString(),
      payerBalanceAfterUnits: payerUsdcAfter.toString(),
      facilitatorBalanceBeforeUnits: facilitatorUsdcBefore.toString(),
      facilitatorBalanceAfterUnits: facilitatorUsdcAfter.toString(),
      paymentRequirements: {
        scheme: requirements.scheme,
        network: requirements.network,
        asset: requirements.asset,
        amount: requirements.amount,
        payTo: requirements.payTo,
        extra: requirements.extra,
      },
    },
    delivery: {
      resourceId: definition.resourceId,
      contentType: definition.contentType,
      contentHash: definition.resourceSha256,
      contentBytes: Buffer.from(envelopeProjection.projection.contentBytes, 'base64').byteLength,
      projection: envelopeProjection.projection,
      component: envelopeProjection.component,
      rawContentArtifact: { path: rawContentPath, sha256: rawContent.sha256 },
      projectionArtifact: projectionPath,
    },
    expenseObservations: {
      advertisedServiceChargeUsdcUnits: offer.amount,
      participantGasExpenseUsdcUnits: '0',
      transactionGasPayer: 'facilitator',
      participantGasCostCount: finalFacts.counts.participantCosts,
      facilitatorGasCost: facilitatorGasCost,
      operatingBudgetUsdcUnits: null,
      participantNativeBalanceBeforeWei: payerNativeBefore.toString(),
      participantNativeBalanceAfterWei: payerNativeAfter.toString(),
    },
    purchaseCounts: {
      purchaseOperations: safeCount(finalFacts.counts.purchaseOperations, 'm2_purchase_operation'),
      payments: safeCount(finalFacts.counts.payments, 'm2_payment'),
      deliveries: safeCount(finalFacts.counts.deliveries, 'm2_delivery'),
      transactionCosts: safeCount(finalFacts.counts.transactionCosts, 'm2_cost'),
    },
  };
}
