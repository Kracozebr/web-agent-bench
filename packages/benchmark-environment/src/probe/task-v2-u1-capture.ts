/**
 * U1 difficulty-v2 reference capture. The planning generation is fenced before
 * a fresh actual generation is created; neither capture is a score or release.
 */
import { randomUUID } from 'node:crypto';
import { decodeFunctionResult, encodeFunctionData, parseAbi, type Hex } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import { apiPath } from './environment.js';
import { sha256Bytes } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import {
  aggregateReferenceCosts,
  readReferenceUsdcBalancesAt,
  submitReferenceUsdcTransfer,
  validateReferenceCostRow,
  type ReferenceUsdcTransferAction,
} from './task-reference-h1h2-drivers.js';
import {
  latestBlock, readCaseDatabaseFacts, readCaseState, readTokenValue, startFreshCaseGeneration,
} from './task-reference-case-drivers.js';
import {
  approveUsdcInSession, readNativeStateInSession, swapUsdcToWethInSession, unwrapWethInSession,
} from './task-native-capture.js';
import {
  inspectSplitCatalog,
  payAndRetrieveSplitResource,
  type SplitParticipantAction,
  type SplitPaymentCapture,
  type SplitReadHandle,
} from './task-split-resource-capture.js';
import { planU1LocalAllocation, u1UsdcShareWithin } from './task-u1-objective.js';
import type { DifficultyProfileSource } from './task-difficulty-v2-capture.js';

const VARIANT_ID = 'bts_u1_ranked_difficulty_v2_reference';
const ACTION_KINDS = ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'] as const;
const EXPECTED_COMPONENTS = [
  { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
  { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amountUsdcUnits: '125000' },
] as const;
const EXPECTED_OBLIGATIONS = [
  { obligationId: 'u1-usdc-payout-1', recipient: '0x3000000000000000000000000000000000000001', amountUsdcUnits: '100000' },
  { obligationId: 'u1-usdc-payout-2', recipient: '0x3000000000000000000000000000000000000002', amountUsdcUnits: '200000' },
] as const;
const EXPECTED_ACTION_PLAN = [
  'inspect_catalog', 'pay:component-1', 'retrieve:component-1', 'pay:component-2', 'retrieve:component-2',
  'transfer:obligation-1', 'transfer:obligation-2', 'approve:exact-input', 'swap:USDC-to-WETH', 'unwrap',
] as const;
const EXPECTED_PLANNING = {
  exactInputUsdcUnits: '1500000', feeTier: 3000, slippageBps: 1000, maximumParticipantGasWei: '6000000000000',
} as const;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
]);

export type U1DifficultyV2ParticipantAction = SplitParticipantAction | {
  kind: 'transfer' | 'approve' | 'swap' | 'unwrap';
  operationId: string;
  rawResponsePath: string;
  rawResponseSha256: string;
};

export type U1DifficultyV2Capture = {
  taskId: 'U1';
  mode: 'ranked';
  capture: Record<string, unknown>;
  session: GenerationSession;
  participantActions: U1DifficultyV2ParticipantAction[];
  caseArtifact: { path: string; sha256: string };
};

type U1Component = { resourceId: string; offerId: string; amountUsdcUnits: string };
type U1Obligation = { obligationId: string; recipient: string; amountUsdcUnits: string };
type U1ProfileTask = {
  components: U1Component[];
  obligations: U1Obligation[];
  planning: typeof EXPECTED_PLANNING;
};
type U1State = {
  blockNumber: string;
  blockHash: string;
  payerAddress: string;
  payerNativeWei: string;
  payerUsdcUnits: string;
  payerWethUnits: string;
  usdcAllowanceUnits: string;
  wethAllowanceUnits: string;
  poolUsdcUnits: string;
  poolWethUnits: string;
  recipientUsdcUnits: Record<string, string>;
};
type RawActionReference = { kind: 'transfer' | 'approve' | 'swap' | 'unwrap'; operationId: string; rawResponsePath: string; rawResponseSha256: string };

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return '{' + entries.map(([key, child]) => JSON.stringify(key) + ':' + canonical(child)).join(',') + '}';
  }
  return JSON.stringify(value) ?? 'null';
}

function assert(value: unknown, code: string): asserts value {
  if (!value) throw new Error(code);
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  const result = record(value);
  if (!result) throw new Error(`task_u1_v2_${label}_invalid`);
  return result;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_u1_v2_${label}_invalid`);
  return value;
}

function uintString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value : String(value ?? '');
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(parsed)) throw new Error(`task_u1_v2_${label}_invalid`);
  return parsed;
}

function manifestOffer(manifest: RuntimeManifest, resourceId: string, offerId: string) {
  const resources = manifest.x402.catalog?.filter((item) => item.resourceId === resourceId) ?? [];
  const resource = resources.length === 1 ? resources[0] : undefined;
  const offers = resource?.offers.filter((item) => item.id === offerId) ?? [];
  const offer = offers.length === 1 ? offers[0] : undefined;
  if (!resource || !offer || !HASH.test(resource.resourceSha256)) throw new Error('task_u1_v2_profile_offer_not_manifest_pinned');
  return { resource, offer };
}

/** Validate the approved, ranked-only U1 inputs against the current manifest. */
export function validateU1DifficultyV2ProfileTask(
  source: DifficultyProfileSource,
  manifest: RuntimeManifest,
  mode: 'ranked' | 'training' = 'ranked',
): U1ProfileTask {
  if (mode !== 'ranked') throw new Error('task_u1_v2_ranked_only');
  const tasks = requiredRecord(source.profile.tasks, 'tasks');
  const task = requiredRecord(tasks.U1, 'profile_task');
  const componentsValue = Array.isArray(task.components) ? task.components : [];
  const obligationsValue = Array.isArray(task.obligations) ? task.obligations : [];
  const planningValue = requiredRecord(task.planning, 'planning');
  const targets = requiredRecord(task.targetSharesBps, 'target_shares');
  const tolerances = requiredRecord(task.assetToleranceBps, 'asset_tolerances');
  if (task.rankedOnly !== true || task.countedParticipantActions !== 10
    || canonical(task.participantActionPlan) !== canonical(EXPECTED_ACTION_PLAN)
    || task.requiredDistinctPaidComponents !== 2 || task.requiredDistinctObligations !== 2
    || canonical(task.allocationAssets) !== canonical(['USDC', 'ETH', 'WETH'])
    || canonical(targets) !== canonical({ USDC: 40, ETH: 9960, WETH: 0 })
    || canonical(tolerances) !== canonical({ USDC: 1, ETH: 1, WETH: 0 })
    || task.toleranceBps !== 1
    || task.cleanupPolicy !== 'exact_approval_can_leave_zero_scope_without_creating_an_extra_allowance'
    || task.swapPrincipalPolicy !== 'pin_from_fresh_pre_action_plan_and_public_quote'
    || canonical(planningValue) !== canonical({
      ...EXPECTED_PLANNING,
      validation: 'fresh_public_quote_and_independent_quoter_before_actual_generation; reject_if_fixed_target_not_reached_at_both_gas_output_bounds',
    })) {
    throw new Error('task_u1_v2_profile_contract_invalid');
  }
  const components = componentsValue.map((value) => {
    const item = requiredRecord(value, 'component');
    return {
      resourceId: requiredString(item.resourceId, 'component_resource_id'),
      offerId: requiredString(item.offerId, 'component_offer_id'),
      amountUsdcUnits: uintString(item.amountUsdcUnits, 'component_amount'),
    };
  });
  const obligations = obligationsValue.map((value) => {
    const item = requiredRecord(value, 'obligation');
    const recipient = requiredString(item.recipient, 'obligation_recipient').toLowerCase();
    if (!ADDRESS.test(recipient)) throw new Error('task_u1_v2_profile_obligation_recipient_invalid');
    return {
      obligationId: requiredString(item.obligationId, 'obligation_id'), recipient,
      amountUsdcUnits: uintString(item.amountUsdcUnits, 'obligation_amount'),
    };
  });
  if (canonical(components) !== canonical(EXPECTED_COMPONENTS)
    || canonical(obligations) !== canonical(EXPECTED_OBLIGATIONS)
    || new Set(components.map((item) => item.resourceId)).size !== 2
    || new Set(obligations.map((item) => item.obligationId)).size !== 2
    || new Set(obligations.map((item) => item.recipient)).size !== 2) {
    throw new Error('task_u1_v2_profile_components_or_obligations_invalid');
  }
  for (const component of components) {
    const pinned = manifestOffer(manifest, component.resourceId, component.offerId);
    if (pinned.offer.amount !== component.amountUsdcUnits) throw new Error('task_u1_v2_profile_offer_amount_mismatch');
  }
  if (manifest.x402.asset.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || !manifest.contracts.pool3000 || manifest.contracts.pool3000.fee !== EXPECTED_PLANNING.feeTier
    || manifest.contracts.pool3000.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
    || manifest.contracts.pool3000.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || manifest.swap.maxSlippageBps < EXPECTED_PLANNING.slippageBps
    || BigInt(manifest.feePolicy.ethUsdcRateNumerator) <= 0n || BigInt(manifest.feePolicy.ethUsdcRateDenominator) <= 0n) {
    throw new Error('task_u1_v2_manifest_route_or_rate_invalid');
  }
  return { components, obligations, planning: { ...EXPECTED_PLANNING } };
}

/** Add the explicitly required zero-WETH allocation constraint to the base plan. */
export function addU1WethZeroConstraint<T extends { allocationAssets: Array<Record<string, unknown>> }>(plan: T) {
  if (plan.allocationAssets.some((item) => item.assetId === 'WETH')) throw new Error('task_u1_v2_weth_constraint_already_present');
  const ethAsset = plan.allocationAssets.find((item) => item.assetId === 'ETH');
  const ethRate = record(ethAsset?.usdcBaseUnitsPerAssetBaseUnit);
  if (!ethRate || typeof ethRate.numerator !== 'string' || typeof ethRate.denominator !== 'string'
    || !/^[1-9][0-9]*$/.test(ethRate.numerator) || !/^[1-9][0-9]*$/.test(ethRate.denominator)) {
    throw new Error('task_u1_v2_eth_conversion_rate_missing');
  }
  return {
    ...plan,
    allocationAssets: [...plan.allocationAssets, {
      // ETH and WETH both use wei base units, so they use the same pinned value ratio.
      assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: ethRate.numerator, denominator: ethRate.denominator },
      targetShareBps: 0, toleranceBps: 0,
    }],
    targetSharesBps: { USDC: 40, ETH: 9960, WETH: 0 },
    assetToleranceBps: { USDC: 1, ETH: 1, WETH: 0 },
  };
}

export function assertU1DifficultyV2ParticipantActions(actions: readonly U1DifficultyV2ParticipantAction[]): void {
  if (actions.length !== ACTION_KINDS.length || actions.some((item, index) =>
    item.kind !== ACTION_KINDS[index] || !UUID.test(item.operationId)
      || typeof item.rawResponsePath !== 'string' || item.rawResponsePath.length === 0
      || !HASH.test(item.rawResponseSha256))) {
    throw new Error('task_u1_v2_participant_action_trace_invalid');
  }
}

/** Public quote numbers are decimal; RPC block identities are hex and hashes are 0x-prefixed. */
export function u1QuoteRpcBlockIdentityMatches(quoteBlockNumber: unknown, rpcBlockNumber: unknown, rpcBlockHash: unknown): boolean {
  if (typeof quoteBlockNumber !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(quoteBlockNumber)
    || typeof rpcBlockNumber !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(rpcBlockNumber)
    || typeof rpcBlockHash !== 'string' || !BLOCK_HASH.test(rpcBlockHash)) return false;
  return BigInt(quoteBlockNumber) === BigInt(rpcBlockNumber);
}

function assertCleanGeneration(facts: Awaited<ReturnType<typeof readCaseDatabaseFacts>>, label: string): void {
  if (facts.operations.length !== 0 || facts.payments.length !== 0 || facts.deliveries.length !== 0
    || facts.transactionCosts.length !== 0 || facts.counts.denials !== '0') {
    throw new Error(`task_u1_v2_${label}_generation_not_clean`);
  }
}

async function readU1StateAt(
  ctx: ProbeContext, session: GenerationSession, blockTag: string, blockHash: string,
  obligations: readonly U1Obligation[], operationId: string | null, label: string,
): Promise<U1State> {
  const [task, balances, poolUsdc, poolWeth] = await Promise.all([
    readCaseState(ctx, { session, blockTag, blockHash, operationId, variantId: VARIANT_ID, label: `${label}-task-state` }),
    readReferenceUsdcBalancesAt(ctx, session, obligations.map((item) => item.recipient), blockTag, operationId, `${label}-balances`, VARIANT_ID),
    readTokenValue(ctx, { token: ctx.runtime.manifest.contracts.usdc.address, functionName: 'balanceOf', args: [ctx.runtime.manifest.contracts.pool3000!.address], blockTag, operationId, variantId: VARIANT_ID, label: `${label}-pool-usdc` }),
    readTokenValue(ctx, { token: ctx.runtime.manifest.contracts.weth.address, functionName: 'balanceOf', args: [ctx.runtime.manifest.contracts.pool3000!.address], blockTag, operationId, variantId: VARIANT_ID, label: `${label}-pool-weth` }),
  ]);
  const state = requiredRecord(task, 'task_state');
  if (balances.blockNumber !== BigInt(blockTag).toString() || balances.blockHash.toLowerCase() !== blockHash.toLowerCase()
    || String(state.blockNumber) !== balances.blockNumber || String(state.blockHash).toLowerCase() !== balances.blockHash.toLowerCase()) {
    throw new Error('task_u1_v2_state_cutoff_mismatch');
  }
  return {
    blockNumber: balances.blockNumber, blockHash: balances.blockHash, payerAddress: balances.payerAddress,
    payerNativeWei: balances.payerNativeWei, payerUsdcUnits: balances.payerUsdcUnits,
    payerWethUnits: requiredString(state.payerWethUnits, 'payer_weth'),
    usdcAllowanceUnits: requiredString(state.usdcRouterAllowanceUnits, 'usdc_allowance'),
    wethAllowanceUnits: requiredString(state.wethRouterAllowanceUnits, 'weth_allowance'),
    poolUsdcUnits: poolUsdc, poolWethUnits: poolWeth, recipientUsdcUnits: balances.recipientUsdcUnits,
  };
}

function sameBaseline(left: U1State, right: U1State): boolean {
  return left.payerNativeWei === right.payerNativeWei && left.payerUsdcUnits === right.payerUsdcUnits
    && left.payerWethUnits === right.payerWethUnits && left.usdcAllowanceUnits === right.usdcAllowanceUnits
    && left.wethAllowanceUnits === right.wethAllowanceUnits && left.poolUsdcUnits === right.poolUsdcUnits
    && left.poolWethUnits === right.poolWethUnits && canonical(left.recipientUsdcUnits) === canonical(right.recipientUsdcUnits);
}

async function fencePlanningGeneration(ctx: ProbeContext, session: GenerationSession): Promise<Record<string, unknown>> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: 'task-u1-v2-planning-generation-fence', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/generations/${session.generationId}/fence`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' }, body: {}, operationId: null, variantId: VARIANT_ID,
  });
  const body = record(response.body);
  if (response.status !== 200 || body?.status !== 'fenced' || body.signerErased !== true) {
    throw new Error(`task_u1_v2_planning_fence_failed_${response.status}`);
  }
  const snapshot = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    variantId: VARIANT_ID, label: 'task-u1-v2-planning-generation-after-fence' });
  const generation = snapshot.generation[0];
  if (snapshot.generation.length !== 1 || generation?.status !== 'fenced'
    || snapshot.operations.length !== 0 || snapshot.payments.length !== 0 || snapshot.deliveries.length !== 0) {
    throw new Error('task_u1_v2_planning_fence_not_independently_confirmed');
  }
  return { status: 'fenced', signerErased: true, databaseGeneration: generation };
}

async function withFenceCleanupDeadline<T>(ctx: ProbeContext, trialDeadlineAt: number, action: () => Promise<T>): Promise<T> {
  const cleanupDeadlineAt = Date.now() + 15_000;
  ctx.transport.setDeadlineAt(cleanupDeadlineAt);
  ctx.database.setDeadlineAt(cleanupDeadlineAt);
  try { return await action(); }
  finally {
    ctx.transport.setDeadlineAt(trialDeadlineAt);
    ctx.database.setDeadlineAt(trialDeadlineAt);
  }
}

function installRawActionRecorder(ctx: ProbeContext): { refs: Map<string, RawActionReference>; restore: () => void } {
  const transport = ctx.transport;
  const original = transport.request.bind(transport);
  const refs = new Map<string, RawActionReference>();
  transport.request = async (input) => {
    let kind: RawActionReference['kind'] | null = null;
    try {
      if (input.boundary === 'actual-tool-http' && input.method.toUpperCase() === 'POST') {
        const match = new URL(input.url).pathname.match(/\/tools\/[^/]+\/(transfer|approve|swap|unwrap)$/);
        if (match) kind = match[1] as RawActionReference['kind'];
      }
    } catch { /* A malformed URL is left for the transport to reject. */ }
    const response = await original({ ...input, ...(kind ? { includeRawResponseBytes: true } : {}) });
    if (kind && response.status >= 200 && response.status < 300) {
      const operationId = response.operationId;
      if (typeof operationId !== 'string' || !UUID.test(operationId)) throw new Error('task_u1_v2_action_operation_id_invalid');
      const text = response.rawBody.toString('utf8');
      if (ctx.secretValues.some((secret) => secret.length > 0 && text.includes(secret))) {
        throw new Error('task_u1_v2_action_response_contains_secret');
      }
      const rawResponsePath = `task-u1-v2/participant-responses/${operationId}-${kind}.json`;
      const rawResponseSha256 = sha256Bytes(response.rawBody);
      await ctx.evidence.writeRawJson(rawResponsePath, response.rawBody, 'actual-tool-http');
      refs.set(operationId, { kind, operationId, rawResponsePath, rawResponseSha256 });
    }
    return response;
  };
  return { refs, restore: () => { transport.request = original; } };
}

function actionRef(refs: Map<string, RawActionReference>, kind: RawActionReference['kind'], operationId: string): RawActionReference {
  const item = refs.get(operationId);
  if (!item || item.kind !== kind) throw new Error(`task_u1_v2_${kind}_raw_response_missing`);
  return item;
}

function assertArtifactBackedActions(ctx: ProbeContext, actions: readonly U1DifficultyV2ParticipantAction[]): void {
  for (const action of actions) {
    const artifact = ctx.evidence.artifacts.find((item) => item.path === action.rawResponsePath);
    if (!artifact || artifact.sha256.toLowerCase() !== action.rawResponseSha256.toLowerCase()) {
      throw new Error('task_u1_v2_action_raw_response_artifact_mismatch');
    }
  }
}

async function captureFreshQuote(ctx: ProbeContext, session: GenerationSession, profile: U1ProfileTask) {
  const amount = profile.planning.exactInputUsdcUnits;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-u1-v2-planning-public-exact-input-quote', method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/quote?inputAssetId=USDC&feeTier=${profile.planning.feeTier}&amountInUnits=${encodeURIComponent(amount)}`),
    headers: { authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId, 'Idempotency-Key': randomUUID() },
    operationId: null, variantId: VARIANT_ID,
  });
  const body = record(response.body);
  const quote = record(body?.quote);
  const pool = ctx.runtime.manifest.contracts.pool3000;
  if (response.status !== 200 || !body || !quote || !pool
    || body.envId !== session.envId || body.generationId !== session.generationId
    || body.route !== 'uniswap-v3-exactInputSingle' || body.inputAssetId !== 'USDC' || body.outputAssetId !== 'WETH'
    || body.fee !== profile.planning.feeTier
    || String(body.tokenIn).toLowerCase() !== ctx.runtime.manifest.contracts.usdc.address.toLowerCase()
    || String(body.tokenOut).toLowerCase() !== ctx.runtime.manifest.contracts.weth.address.toLowerCase()
    || String(body.poolAddress).toLowerCase() !== pool.address.toLowerCase()
    || String(body.poolCodeHash).toLowerCase() !== pool.codeHash.toLowerCase()
    || body.quoteStatus !== 'observed' || String(body.requestedAmountInUnits) !== amount
    || quote.inputAssetId !== 'USDC' || quote.outputAssetId !== 'WETH' || quote.feeTier !== profile.planning.feeTier
    || String(quote.poolAddress).toLowerCase() !== pool.address.toLowerCase()
    || String(quote.poolCodeHash).toLowerCase() !== pool.codeHash.toLowerCase()
    || String(quote.amountInUnits) !== amount || String(quote.blockNumber) !== String(body.blockNumber)) {
    throw new Error('task_u1_v2_public_quote_identity_invalid');
  }
  const quoteBlockNumber = uintString(body.blockNumber, 'quote_block_number');
  const quotedOutputWei = uintString(quote.amountOutUnits, 'quote_output');
  if (BigInt(quotedOutputWei) === 0n) throw new Error('task_u1_v2_public_quote_output_zero');
  const quoteBlockTag = `0x${BigInt(quoteBlockNumber).toString(16)}`;
  const calldata = encodeFunctionData({ abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', args: [{
    tokenIn: ctx.runtime.manifest.contracts.usdc.address as `0x${string}`,
    tokenOut: ctx.runtime.manifest.contracts.weth.address as `0x${string}`,
    amountIn: BigInt(amount), fee: profile.planning.feeTier, sqrtPriceLimitX96: 0n,
  }] });
  const quoterCall = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_call', params: [{ to: ctx.runtime.manifest.contracts.quoterV2.address, data: calldata }, quoteBlockTag],
    requestedBlock: quoteBlockTag, operationId: null, variantId: VARIANT_ID, label: 'task-u1-v2-independent-fee3000-quoter-v2',
  });
  if (typeof quoterCall.result !== 'string' || !/^0x[0-9a-f]{256}$/i.test(quoterCall.result)) {
    throw new Error('task_u1_v2_independent_quote_result_invalid');
  }
  const decoded = decodeFunctionResult({ abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', data: quoterCall.result as Hex });
  if (decoded[0].toString() !== quotedOutputWei) throw new Error('task_u1_v2_independent_quote_output_mismatch');
  const block = await ctx.rpc.block({ url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: quoteBlockTag,
    operationId: null, variantId: VARIANT_ID, label: 'task-u1-v2-public-quote-block-identity' });
  if (!u1QuoteRpcBlockIdentityMatches(quoteBlockNumber, block.number, block.hash)) throw new Error('task_u1_v2_quote_block_identity_invalid');
  const minimumOutputWei = (BigInt(quotedOutputWei) * BigInt(10_000 - profile.planning.slippageBps) / 10_000n).toString();
  if (BigInt(minimumOutputWei) === 0n) throw new Error('task_u1_v2_minimum_output_zero');
  const rawBody = response.rawBody;
  if (ctx.secretValues.some((secret) => secret.length > 0 && rawBody.toString('utf8').includes(secret))) {
    throw new Error('task_u1_v2_public_quote_contains_secret');
  }
  const rawResponsePath = 'task-u1-v2/planning/public-quote-response.json';
  await ctx.evidence.writeRawJson(rawResponsePath, rawBody, 'actual-tool-http');
  return {
    response: body,
    rawResponsePath,
    rawResponseSha256: sha256Bytes(rawBody),
    quoteBlockNumber,
    quoteBlockHash: block.hash.toLowerCase(),
    quoteData: calldata,
    quoterAddress: ctx.runtime.manifest.contracts.quoterV2.address.toLowerCase(),
    independentResult: quoterCall.result,
    decoded: { amountOutWei: decoded[0].toString(), sqrtPriceX96After: decoded[1].toString(),
      initializedTicksCrossed: decoded[2].toString(), gasEstimate: decoded[3].toString() },
    quotedOutputWei,
    minimumOutputWei,
  };
}

async function persistDeliveryProjection(ctx: ProbeContext, item: SplitPaymentCapture, component: U1Component, index: number) {
  const projection = item.deliveryProjection;
  if (projection.component.resourceId !== component.resourceId
    || projection.contentBytesSha256.toLowerCase() !== manifestOffer(ctx.runtime.manifest, component.resourceId, component.offerId).resource.resourceSha256.toLowerCase()) {
    throw new Error('task_u1_v2_component_delivery_projection_mismatch');
  }
  const projectionPath = `task-u1-v2/delivery-projections/${item.operationId}-component-${index + 1}.json`;
  await ctx.evidence.writeObservation(projectionPath, `task-u1-v2-delivery-projection-${index + 1}`, {
    schemaVersion: 'bts-u1-v2-delivery-projection/v1', boundary: 'actual-tool-http', operationId: item.operationId,
    variantId: VARIANT_ID, envId: ctx.env.envId, resourceId: component.resourceId, offerId: component.offerId,
    projection: projection.projection, component: projection.component, contentBytesSha256: projection.contentBytesSha256,
  });
  return {
    componentId: component.resourceId, resourceId: component.resourceId, offerId: component.offerId,
    amountUsdcUnits: component.amountUsdcUnits,
    resourceSha256: manifestOffer(ctx.runtime.manifest, component.resourceId, component.offerId).resource.resourceSha256,
    validatedContentSha256: projection.contentBytesSha256, contentBytes: Buffer.from(projection.projection.contentBytes, 'base64').byteLength,
    deliveryOperationId: item.operationId, paymentTransactionHash: item.transactionHash,
    paymentReceipt: item.paymentReceipt, settlementReceipt: item.settlementReceipt,
    deliveryProjectionArtifact: projectionPath, deliveredContentArtifact: item.deliveryContentPath,
    contentArtifactSha256: item.deliveryContentSha256, validator: projection.component.validator,
    permittedSources: projection.component.sourceIds,
  };
}

function operationFor(facts: Awaited<ReturnType<typeof readCaseDatabaseFacts>>, operationId: string) {
  return facts.operations.find((row) => String(row.operation_id) === operationId);
}

function validateDurableEffects(input: {
  ctx: ProbeContext; session: GenerationSession; catalog: SplitReadHandle;
  payments: readonly SplitPaymentCapture[]; components: readonly U1Component[];
  transfers: readonly ReferenceUsdcTransferAction[]; approval: { action: { operationId: string; transactionHash: string } };
  swap: { action: { operationId: string; transactionHash: string } };
  unwrap: { action: { operationId: string; transactionHash: string } };
}) {
  return readCaseDatabaseFacts(input.ctx, input.session, 'u1-v2-final-database-facts', VARIANT_ID).then((facts) => {
    type ExpectedCostAction = { operationId: string; transactionHash: string; kind: string; status: string;
      role: 'facilitator' | 'participant'; resource?: U1Component };
    const transactionActions: ExpectedCostAction[] = [
      ...input.payments.map((item, index) => {
        const resource = input.components[index];
        if (!resource) throw new Error('task_u1_v2_payment_component_binding_missing');
        return { operationId: item.operationId, transactionHash: item.transactionHash,
          kind: 'purchase', status: 'delivered', role: 'facilitator' as const, resource };
      }),
      ...input.transfers.map((item) => ({ operationId: item.operationId, transactionHash: item.transactionHash,
        kind: 'transfer', status: 'settled', role: 'participant' as const })),
      { operationId: input.approval.action.operationId, transactionHash: input.approval.action.transactionHash,
        kind: 'approve', status: 'settled', role: 'participant' as const },
      { operationId: input.swap.action.operationId, transactionHash: input.swap.action.transactionHash,
        kind: 'swap', status: 'settled', role: 'participant' as const },
      { operationId: input.unwrap.action.operationId, transactionHash: input.unwrap.action.transactionHash,
        kind: 'unwrap', status: 'settled', role: 'participant' as const },
    ];
    const expectedIds = new Set([input.catalog.operationId, ...transactionActions.map((item) => item.operationId)]);
    if (expectedIds.size !== 8 || facts.operations.length !== 8 || facts.payments.length !== 2 || facts.deliveries.length !== 2
      || facts.transactionCosts.length !== 7 || facts.counts.denials !== '0' || facts.counts.purchaseOperations !== '2'
      || facts.counts.payments !== '2' || facts.counts.deliveries !== '2' || facts.counts.transactionCosts !== '7'
      || facts.counts.participantCosts !== '5' || facts.counts.selectedExecutions !== '5'
      || facts.operations.some((row) => !expectedIds.has(String(row.operation_id)))) {
      throw new Error('task_u1_v2_final_database_effect_counts_invalid');
    }
    const catalogOperation = operationFor(facts, input.catalog.operationId);
    if (!catalogOperation || catalogOperation.operation_kind !== 'catalog' || catalogOperation.status !== 'accepted'
      || facts.payments.some((row) => String(row.operation_id) === input.catalog.operationId)
      || facts.deliveries.some((row) => String(row.operation_id) === input.catalog.operationId)) {
      throw new Error('task_u1_v2_catalog_read_durable_effect_invalid');
    }
    const validatedCosts = transactionActions.map((expected) => {
      const operation = operationFor(facts, expected.operationId);
      const matchingCosts = facts.transactionCosts.filter((row) => String(row.operation_id) === expected.operationId);
      if (!operation || operation.operation_kind !== expected.kind || operation.status !== expected.status
        || operation.receipt_status !== 'success' || String(operation.transaction_hash).toLowerCase() !== expected.transactionHash.toLowerCase()
        || matchingCosts.length !== 1) throw new Error('task_u1_v2_operation_or_cost_binding_invalid');
      if (expected.resource && (String(operation.selected_resource_id) !== expected.resource.resourceId
        || String(operation.selected_offer_id) !== expected.resource.offerId
        || String(operation.selected_amount_units) !== expected.resource.amountUsdcUnits)) {
        throw new Error('task_u1_v2_purchase_binding_invalid');
      }
      const payment = expected.role === 'facilitator'
        ? facts.payments.find((row) => String(row.operation_id) === expected.operationId) : undefined;
      const row = matchingCosts[0]!;
      const cost = validateReferenceCostRow(row, input.ctx.runtime.manifest, {
        operationId: expected.operationId, transactionHash: expected.transactionHash, payerRole: expected.role,
        payerAddress: expected.role === 'participant' ? input.session.payerAddress : String(payment?.facilitator_address),
        manifestSha256: input.ctx.runtime.manifestSha256,
      });
      if (String(row.gas_cost_wei) !== cost.gasCostWei) throw new Error('task_u1_v2_cost_receipt_mismatch');
      return cost;
    });
    const serviceUnits = facts.payments.reduce((sum, row) => sum + BigInt(String(row.amount_units)), 0n);
    const expectedServiceUnits = input.components.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n);
    if (serviceUnits !== expectedServiceUnits) throw new Error('task_u1_v2_service_charge_total_invalid');
    for (const [index, component] of input.components.entries()) {
      const payment = input.payments[index]!;
      const row = facts.payments.find((item) => String(item.operation_id) === payment.operationId);
      const delivery = facts.deliveries.find((item) => String(item.operation_id) === payment.operationId);
      if (!row || !delivery || String(row.amount_units) !== component.amountUsdcUnits
        || String(row.token_delta_units) !== component.amountUsdcUnits
        || String(row.payer_address).toLowerCase() !== input.session.payerAddress.toLowerCase()
        || String(row.transaction_hash).toLowerCase() !== payment.transactionHash.toLowerCase()
        || String(delivery.resource_id) !== component.resourceId
        || String(delivery.content_sha256).toLowerCase() !== manifestOffer(input.ctx.runtime.manifest, component.resourceId, component.offerId).resource.resourceSha256.toLowerCase()) {
        throw new Error('task_u1_v2_payment_delivery_database_binding_invalid');
      }
    }
    return { facts, costs: aggregateReferenceCosts(validatedCosts), serviceUnits };
  });
}

function assetShareWithin(value: bigint, total: bigint, targetBps: number, toleranceBps: number): boolean {
  if (value < 0n || total <= 0n) return false;
  return value * 10_000n >= total * BigInt(Math.max(0, targetBps - toleranceBps))
    && value * 10_000n <= total * BigInt(Math.min(10_000, targetBps + toleranceBps));
}

/** Capture ranked U1 using a fresh quote/plan and the ten required participant actions. */
export async function captureU1DifficultyV2Task(
  ctx: ProbeContext,
  source: DifficultyProfileSource,
  trialDeadlineAt: number,
): Promise<U1DifficultyV2Capture> {
  const startedAt = Date.now();
  const profile = validateU1DifficultyV2ProfileTask(source, ctx.runtime.manifest, 'ranked');
  if (sha256Bytes(source.bytes).toLowerCase() !== source.sha256.toLowerCase()) throw new Error('task_u1_v2_profile_source_hash_invalid');
  const planningSession = await startFreshCaseGeneration(ctx, { caseId: 'u1', scenarioId: 'BEF-SC-009', variantId: VARIANT_ID, labelSuffix: 'planning' });
  const planBlock = await latestBlock(ctx, null, VARIANT_ID, 'task-u1-v2-planning-initial-cutoff');
  const plannedInitial = await readU1StateAt(ctx, planningSession, planBlock.tag, planBlock.hash, profile.obligations, null, 'task-u1-v2-planning-initial');
  const planningFacts = await readCaseDatabaseFacts(ctx, planningSession, 'u1-v2-planning-before-quote', VARIANT_ID);
  assertCleanGeneration(planningFacts, 'planning');
  if (plannedInitial.payerWethUnits !== '0' || plannedInitial.usdcAllowanceUnits !== '0' || plannedInitial.wethAllowanceUnits !== '0') {
    throw new Error('task_u1_v2_planning_initial_weth_or_allowance_invalid');
  }
  const quote = await captureFreshQuote(ctx, planningSession, profile);
  const allocationPlan = planU1LocalAllocation({
    initialUsdcUnits: plannedInitial.payerUsdcUnits, initialNativeWei: plannedInitial.payerNativeWei,
    paidServiceUnits: profile.components.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n).toString(),
    payoutUnits: profile.obligations.map((item) => item.amountUsdcUnits),
    swapInputUsdcUnits: profile.planning.exactInputUsdcUnits,
    minimumNativeOutputWei: quote.minimumOutputWei, quotedNativeOutputWei: quote.quotedOutputWei,
    maximumParticipantGasWei: profile.planning.maximumParticipantGasWei,
    ethUsdcRateNumerator: ctx.runtime.manifest.feePolicy.ethUsdcRateNumerator,
    ethUsdcRateDenominator: ctx.runtime.manifest.feePolicy.ethUsdcRateDenominator,
  });
  const plan = addU1WethZeroConstraint(allocationPlan);
  const planDocument = {
    schemaVersion: 'bts-u1-difficulty-v2-pre-action-plan/v1',
    classification: 'fresh_local_pre_execution_plan_not_release_or_execution_proof',
    taskId: 'U1', mode: 'ranked', profilePath: source.path, profileSha256: source.sha256,
    manifestSha256: ctx.runtime.manifestSha256, planningGeneration: { envId: planningSession.envId, generationId: planningSession.generationId },
    initialState: plannedInitial, quote, plan, participantActionPlan: [...EXPECTED_ACTION_PLAN],
  };
  const planBytes = Buffer.from(`${JSON.stringify(planDocument, null, 2)}\n`, 'utf8');
  const planPath = 'task-u1-v2/planning/pre-action-plan.json';
  await ctx.evidence.writeRawJson(planPath, planBytes, 'pre-execution-u1-difficulty-v2-plan');
  const planningFence = await withFenceCleanupDeadline(ctx, trialDeadlineAt, () => fencePlanningGeneration(ctx, planningSession));
  // Preserve the prior generation identity for reset validation, but avoid fencing it twice
  // if creation of the actual generation fails after this confirmed planning fence.
  if (ctx.primarySession?.generationId === planningSession.generationId) ctx.primarySession = null;

  const session = await startFreshCaseGeneration(ctx, { caseId: 'u1', scenarioId: 'BEF-SC-009', variantId: VARIANT_ID, labelSuffix: 'actual' });
  const actualBlock = await latestBlock(ctx, null, VARIANT_ID, 'task-u1-v2-actual-initial-cutoff');
  const actualInitial = await readU1StateAt(ctx, session, actualBlock.tag, actualBlock.hash, profile.obligations, null, 'task-u1-v2-actual-initial');
  const actualFacts = await readCaseDatabaseFacts(ctx, session, 'u1-v2-actual-before-actions', VARIANT_ID);
  assertCleanGeneration(actualFacts, 'actual');
  if (!sameBaseline(plannedInitial, actualInitial)) throw new Error('task_u1_v2_planning_actual_baseline_mismatch');
  if (actualInitial.payerWethUnits !== '0' || actualInitial.usdcAllowanceUnits !== '0' || actualInitial.wethAllowanceUnits !== '0') {
    throw new Error('task_u1_v2_actual_initial_weth_or_allowance_invalid');
  }

  const recorder = installRawActionRecorder(ctx);
  let catalog: SplitReadHandle;
  let payments: SplitPaymentCapture[];
  let transfers: ReferenceUsdcTransferAction[];
  let approval: Awaited<ReturnType<typeof approveUsdcInSession>>;
  let swap: Awaited<ReturnType<typeof swapUsdcToWethInSession>>;
  let unwrap: Awaited<ReturnType<typeof unwrapWethInSession>>;
  try {
    catalog = await inspectSplitCatalog(ctx, session, { variantId: VARIANT_ID, label: 'u1-v2-catalog' });
    payments = [];
    for (const [index, component] of profile.components.entries()) {
      payments.push(await payAndRetrieveSplitResource(ctx, session,
        { resourceId: component.resourceId, offerId: component.offerId }, catalog,
        { variantId: VARIANT_ID, label: `u1-v2-component-${index + 1}` }));
    }
    transfers = [];
    for (const [index, obligation] of profile.obligations.entries()) {
      transfers.push(await submitReferenceUsdcTransfer(ctx, session, {
        recipient: obligation.recipient, amountUnits: obligation.amountUsdcUnits, index, variantId: VARIANT_ID,
      }));
    }
    const beforeApproval = await readNativeStateInSession(ctx, session, 'task-u1-v2-before-exact-approval', VARIANT_ID);
    const serviceUnits = profile.components.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n);
    const payoutUnits = profile.obligations.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n);
    if (beforeApproval.payerWethUnits !== '0' || beforeApproval.usdcAllowanceUnits !== '0' || beforeApproval.wethAllowanceUnits !== '0'
      || BigInt(actualInitial.payerUsdcUnits) - BigInt(beforeApproval.payerUsdcUnits) !== serviceUnits + payoutUnits
      || beforeApproval.poolUsdcUnits !== actualInitial.poolUsdcUnits || beforeApproval.poolWethUnits !== actualInitial.poolWethUnits) {
      throw new Error('task_u1_v2_pre_approval_state_invalid');
    }
    const exactInput = BigInt(profile.planning.exactInputUsdcUnits);
    approval = await approveUsdcInSession(ctx, session, exactInput, VARIANT_ID, 'u1-v2-approve-exact-swap-input');
    if (approval.state.usdcAllowanceUnits !== exactInput.toString() || approval.state.payerUsdcUnits !== beforeApproval.payerUsdcUnits
      || approval.state.payerWethUnits !== '0' || approval.state.wethAllowanceUnits !== '0'
      || approval.state.poolUsdcUnits !== beforeApproval.poolUsdcUnits || approval.state.poolWethUnits !== beforeApproval.poolWethUnits) {
      throw new Error('task_u1_v2_exact_approval_effect_invalid');
    }
    swap = await swapUsdcToWethInSession(ctx, session, {
      amount: exactInput, minimumOutput: BigInt(quote.minimumOutputWei), recipient: session.payerAddress,
      variantId: VARIANT_ID, label: 'u1-v2-usdc-to-weth',
    });
    if (swap.output < BigInt(quote.minimumOutputWei) || swap.input !== exactInput
      || BigInt(approval.state.usdcAllowanceUnits) - BigInt(swap.state.usdcAllowanceUnits) !== exactInput
      || swap.state.usdcAllowanceUnits !== '0' || swap.state.wethAllowanceUnits !== '0'
      || BigInt(approval.state.payerUsdcUnits) - BigInt(swap.state.payerUsdcUnits) !== exactInput
      || BigInt(swap.state.payerWethUnits) - BigInt(approval.state.payerWethUnits) !== swap.output
      || BigInt(swap.state.poolUsdcUnits) - BigInt(approval.state.poolUsdcUnits) !== exactInput
      || BigInt(approval.state.poolWethUnits) - BigInt(swap.state.poolWethUnits) !== swap.output) {
      throw new Error('task_u1_v2_swap_effect_or_exact_allowance_invalid');
    }
    unwrap = await unwrapWethInSession(ctx, session, swap.output, VARIANT_ID, 'u1-v2-unwrap-all-weth');
    if (unwrap.state.payerWethUnits !== '0' || unwrap.state.usdcAllowanceUnits !== '0' || unwrap.state.wethAllowanceUnits !== '0'
      || BigInt(swap.state.payerWethUnits) - BigInt(unwrap.state.payerWethUnits) !== swap.output
      || BigInt(unwrap.state.payerNativeWei) - BigInt(swap.state.payerNativeWei) !== swap.output - unwrap.gasCostWei
      || unwrap.state.payerUsdcUnits !== swap.state.payerUsdcUnits
      || unwrap.state.poolUsdcUnits !== swap.state.poolUsdcUnits || unwrap.state.poolWethUnits !== swap.state.poolWethUnits) {
      throw new Error('task_u1_v2_unwrap_or_zero_weth_invalid');
    }
  } finally {
    recorder.restore();
  }

  const participantActions: U1DifficultyV2ParticipantAction[] = [
    catalog!.participantAction,
    ...payments!.flatMap((item) => item.participantActions),
    ...transfers!.map((item) => actionRef(recorder.refs, 'transfer', item.operationId)),
    actionRef(recorder.refs, 'approve', approval!.action.operationId),
    actionRef(recorder.refs, 'swap', swap!.action.operationId),
    actionRef(recorder.refs, 'unwrap', unwrap!.action.operationId),
  ];
  assertU1DifficultyV2ParticipantActions(participantActions);
  assertArtifactBackedActions(ctx, participantActions);

  const components = await Promise.all(payments!.map((item, index) => persistDeliveryProjection(ctx, item, profile.components[index]!, index)));
  if (new Set(components.map((item) => item.resourceId)).size !== 2
    || components.some((item, index) => item.resourceId !== profile.components[index]!.resourceId
      || item.offerId !== profile.components[index]!.offerId || item.amountUsdcUnits !== profile.components[index]!.amountUsdcUnits)) {
    throw new Error('task_u1_v2_two_distinct_components_invalid');
  }

  const durable = await validateDurableEffects({ ctx, session, catalog: catalog!, payments: payments!, components: profile.components,
    transfers: transfers!, approval: approval!, swap: swap!, unwrap: unwrap! });
  if (durable.costs.participantGasWei > BigInt(profile.planning.maximumParticipantGasWei)) {
    throw new Error('task_u1_v2_participant_gas_ceiling_exceeded');
  }
  const serviceUnits = durable.serviceUnits;
  const declaredDexFeeUnits = (BigInt(profile.planning.exactInputUsdcUnits) * BigInt(profile.planning.feeTier) + 999_999n) / 1_000_000n;
  const cutoff = await latestBlock(ctx, unwrap!.action.operationId, VARIANT_ID, 'task-u1-v2-final-common-cutoff');
  if (BigInt(cutoff.number) < BigInt(unwrap!.receipt.blockNumber)) throw new Error('task_u1_v2_cutoff_precedes_unwrap_receipt');
  const final = await readU1StateAt(ctx, session, cutoff.tag, cutoff.hash, profile.obligations, unwrap!.action.operationId, 'task-u1-v2-final');
  if (final.blockNumber !== cutoff.number || final.blockHash.toLowerCase() !== cutoff.hash.toLowerCase()) {
    throw new Error('task_u1_v2_final_cutoff_identity_invalid');
  }
  const payoutResults = profile.obligations.map((obligation) => {
    const initial = actualInitial.recipientUsdcUnits[obligation.recipient];
    const finalUnits = final.recipientUsdcUnits[obligation.recipient];
    assert(initial !== undefined && finalUnits !== undefined
      && BigInt(finalUnits) - BigInt(initial) === BigInt(obligation.amountUsdcUnits), 'task_u1_v2_exact_payout_delta_invalid');
    const transfer = transfers!.find((item) => item.recipient.toLowerCase() === obligation.recipient);
    assert(transfer && transfer.amountUnits === obligation.amountUsdcUnits, 'task_u1_v2_transfer_obligation_binding_invalid');
    return { ...obligation, initialUsdcUnits: initial, finalUsdcUnits: finalUnits, operationId: transfer.operationId,
      transactionHash: transfer.transactionHash, receiptBlockNumber: transfer.receiptBlockNumber, receiptBlockHash: transfer.receiptBlockHash,
      exactDeltaVerified: true };
  });
  const totalUsdcDebits = serviceUnits + profile.obligations.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n)
    + BigInt(profile.planning.exactInputUsdcUnits);
  assert(BigInt(actualInitial.payerUsdcUnits) - BigInt(final.payerUsdcUnits) === totalUsdcDebits,
    'task_u1_v2_payer_usdc_delta_invalid');
  assert(BigInt(final.payerNativeWei) - BigInt(actualInitial.payerNativeWei) === swap!.output - durable.costs.participantGasWei,
    'task_u1_v2_payer_native_delta_invalid');
  assert(final.payerWethUnits === '0' && final.usdcAllowanceUnits === '0' && final.wethAllowanceUnits === '0',
    'task_u1_v2_final_weth_or_allowance_nonzero');
  assert(BigInt(final.poolUsdcUnits) - BigInt(actualInitial.poolUsdcUnits) === BigInt(profile.planning.exactInputUsdcUnits)
    && BigInt(actualInitial.poolWethUnits) - BigInt(final.poolWethUnits) === swap!.output,
  'task_u1_v2_final_pool_delta_invalid');
  const usdcValue = BigInt(final.payerUsdcUnits) * BigInt(durable.costs.rateDenominator);
  const nativeValue = BigInt(final.payerNativeWei) * BigInt(durable.costs.rateNumerator);
  const totalValue = usdcValue + nativeValue;
  const usdcWithin = u1UsdcShareWithin({ usdcUnits: BigInt(final.payerUsdcUnits), nativeWei: BigInt(final.payerNativeWei),
    rateNumerator: BigInt(durable.costs.rateNumerator), rateDenominator: BigInt(durable.costs.rateDenominator), targetShareBps: 40, toleranceBps: 1 });
  const ethWithin = assetShareWithin(nativeValue, totalValue, 9960, 1);
  const reserveWithin = BigInt(final.payerNativeWei) >= BigInt(plan.nativeReserveWei);
  assert(usdcWithin && ethWithin && reserveWithin, 'task_u1_v2_final_allocation_or_native_reserve_invalid');

  const capture: Record<string, unknown> = {
    schemaVersion: 'bts-task-u1-difficulty-v2-reference/v1', classification: 'local_fork_public_tool_evidence_not_task_acceptance',
    status: 'captured_candidate', releaseReadiness: 'blocked', taskId: 'U1', mode: 'ranked', countedParticipantActions: 10,
    participantToolProtocol: 'separate_payment_delivery_v2', participantActions,
    sourceProfile: { path: source.path, sha256: source.sha256, mode: 'ranked' }, manifestSha256: ctx.runtime.manifestSha256,
    environment: { envId: session.envId, generationId: session.generationId, participantId: session.participantId,
      payerAddress: session.payerAddress.toLowerCase(), chainId: ctx.runtime.manifest.local.chainId,
      forkBlock: ctx.runtime.manifest.local.forkBlock },
    planning: { generationId: planningSession.generationId, initialState: plannedInitial, quote,
      planPath, planSha256: sha256Bytes(planBytes), fence: planningFence },
    initialState: actualInitial,
    catalog: { operationId: catalog!.operationId, rawResponsePath: catalog!.rawResponsePath,
      rawResponseSha256: catalog!.rawResponseSha256, projection: catalog!.catalogProjection },
    components,
    obligations: payoutResults,
    actions: {
      payments: payments!.map((item) => ({ operationId: item.operationId, transactionHash: item.transactionHash,
        paymentReceipt: item.paymentReceipt, settlementReceipt: item.settlementReceipt, facilitatorGas: item.facilitatorGas,
        deliveryContentPath: item.deliveryContentPath, deliveryContentSha256: item.deliveryContentSha256 })),
      transfers: transfers!.map((item) => ({ ...item, participantAction: actionRef(recorder.refs, 'transfer', item.operationId) })),
      approval: { operationId: approval!.action.operationId, transactionHash: approval!.action.transactionHash,
        amountUnits: profile.planning.exactInputUsdcUnits, gasCostWei: approval!.gasCostWei.toString(), persistedCost: approval!.persistedCost },
      swap: { operationId: swap!.action.operationId, transactionHash: swap!.action.transactionHash, feeTier: profile.planning.feeTier,
        amountInUnits: profile.planning.exactInputUsdcUnits, amountOutMinimumWei: quote.minimumOutputWei, observedWethOutputWei: swap!.output.toString(),
        finalAllowanceUnits: swap!.state.usdcAllowanceUnits, gasCostWei: swap!.gasCostWei.toString(), persistedCost: swap!.persistedCost },
      unwrap: { operationId: unwrap!.action.operationId, transactionHash: unwrap!.action.transactionHash,
        amountWei: swap!.output.toString(), finalWethUnits: unwrap!.state.payerWethUnits, gasCostWei: unwrap!.gasCostWei.toString(), persistedCost: unwrap!.persistedCost },
    },
    finalCutoff: { blockNumber: final.blockNumber, blockHash: final.blockHash, payerUsdcUnits: final.payerUsdcUnits,
      payerNativeWei: final.payerNativeWei, payerWethUnits: final.payerWethUnits,
      usdcRouterAllowanceUnits: final.usdcAllowanceUnits, wethRouterAllowanceUnits: final.wethAllowanceUnits,
      poolUsdcUnits: final.poolUsdcUnits, poolWethUnits: final.poolWethUnits, recipientUsdcUnits: final.recipientUsdcUnits,
      allocation: { USDC: { shareBps: 40, toleranceBps: 1, withinTarget: usdcWithin },
        ETH: { shareBps: 9960, toleranceBps: 1, withinTarget: ethWithin },
        WETH: { balanceUnits: final.payerWethUnits, targetUnits: '0', toleranceUnits: '0', withinTarget: final.payerWethUnits === '0' },
        nativeReserveWei: plan.nativeReserveWei, reserveWithinTarget: reserveWithin } },
    observedCosts: { serviceChargesUsdcUnits: serviceUnits.toString(), declaredDexFeeUsdcUnits: declaredDexFeeUnits.toString(),
      dexFeeFormula: 'ceil(exactInputUsdcUnits * feeTier / 1000000); reported as declared route expense, not a receipt measurement',
      participantGasWei: durable.costs.participantGasWei.toString(), participantAggregateGasUsdcUnits: durable.costs.participantAggregateGasUsdcUnits.toString(),
      facilitatorGasWei: durable.costs.facilitatorGasWei.toString(), facilitatorAggregateGasUsdcUnits: durable.costs.facilitatorAggregateGasUsdcUnits.toString(),
      gasConversion: 'sum verified receipt gas wei by payer role, then apply pinned rational rate and floor once',
      rateNumerator: durable.costs.rateNumerator, rateDenominator: durable.costs.rateDenominator,
      baseL1FeeStatus: 'unmodelled', receipts: durable.costs.costs },
    durableState: { operations: durable.facts.operations, payments: durable.facts.payments, deliveries: durable.facts.deliveries,
      transactionCosts: durable.facts.transactionCosts, effectCounts: durable.facts.counts },
    generationFenceBoundary: 'actual generation is fenced by task-u1-main after this capture returns',
    noReleaseActivation: true, noGradePosted: true,
    acceptanceBoundary: 'No authoritative admitted-task action cutoff was available; this is reference-only local-fork evidence.',
    elapsedMs: Date.now() - startedAt,
  };
  const casePath = 'task-u1-v2/u1-ranked-reference.json';
  await ctx.evidence.writeObservation(casePath, 'task-u1-v2-ranked-reference', {
    ...capture, boundary: 'actual-tool-http-local-chain-readonly-and-readonly-database', operationId: unwrap!.action.operationId,
    variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId,
  });
  const artifact = ctx.evidence.artifacts.find((item) => item.path === casePath);
  assert(artifact, 'task_u1_v2_case_artifact_missing');
  return { taskId: 'U1', mode: 'ranked', capture, session, participantActions, caseArtifact: { path: artifact.path, sha256: artifact.sha256 } };
}
