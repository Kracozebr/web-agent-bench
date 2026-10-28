/**
 * V2 reverse-swap reference captures for M4 and H3.
 * These are local-fork observations, not task acceptance or release evidence.
 */
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import pg from 'pg';
import { decodeEventLog, decodeFunctionResult, encodeFunctionData, parseAbi } from 'viem';
import type { Address, Hex } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import { apiPath } from './environment.js';
import { sanitizeValue, sha256Bytes } from './evidence.js';
import type { ProbeContext, GenerationSession } from './runner.js';
import type { SelectedExecutionTransactionEvidence } from './rpc.js';
import { transferEvents } from './rpc.js';
import {
  latestBlock,
  readCaseDatabaseFacts,
  readCaseState,
  readTokenValue,
  startFreshCaseGeneration,
} from './task-reference-case-drivers.js';
import { projectRouteDelivery } from './task-route-reference.js';
import { inspectSplitOffer, payAndRetrieveSplitResource } from './task-split-resource-capture.js';
import type { SplitParticipantAction, SplitPaymentCapture } from './task-split-resource-capture.js';

const { Pool } = pg;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROFILE_PATH = 'infrastructure/owner-identity/task-difficulty-profile-v2.json';
const PROFILE_ID = 'bts-task-difficulty-v2';
const PROFILE_SCHEMA = 'bts-task-case-input-profile/v2';
const VARIANT_ID = 'bts_v2_reverse_swap_reference';
const GAS_LIMITS = { wrap: '150000', approve: '100000', swap: '400000' } as const;
const WETH_ABI = parseAbi([
  'function deposit() payable',
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner,address spender) view returns (uint256)',
  'event Deposit(address indexed dst,uint256 wad)',
]);
const APPROVE_ABI = parseAbi(['function approve(address spender,uint256 amount) returns (bool)']);
const APPROVAL_ABI = parseAbi(['event Approval(address indexed owner,address indexed spender,uint256 value)']);
const SWAP_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params) payable returns (uint256 amountOut)',
]);
const POOL_SWAP_ABI = parseAbi([
  'event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)',
]);

type DifficultyMode = 'ranked' | 'training';
type FeeTier = 500 | 3000;
type CaseName = 'm4-ranked' | 'm4-training' | 'h3-ranked';
export type ReverseSwapProfileSource = { profile: Record<string, unknown>; path: string; sha256: string };
type PoolIdentity = { address: string; codeHash: string; token0: string; token1: string; fee: number };
type QuotePlan = {
  feeTier: FeeTier;
  poolAddress: string;
  poolCodeHash: string;
  inputAssetId: 'WETH';
  outputAssetId: 'USDC';
  amountInUnits: string;
  amountOutUnits: string;
  minimumOutputUnits: string;
  slippageBps: number;
  blockNumber: string;
  blockHash: string;
  independentQuoterV2OutputUnits: string;
  publicQuoteArtifact: { path: string; sha256: string };
  planArtifact: { path: string; sha256: string };
};
type CaseState = {
  blockNumber: string;
  blockHash: string;
  payerAddress: string;
  payerNativeEthWei: string;
  payerWethUnits: string;
  payerUsdcUnits: string;
  wethRouterAllowanceUnits: string;
  usdcRouterAllowanceUnits: string;
  poolWethUnits: string;
  poolUsdcUnits: string;
};
type CapturedAction = {
  kind: 'wrap' | 'approve' | 'swap';
  operationId: string;
  transactionHash: string;
  idempotencyKeySha256: string;
  selectedAction: Record<string, unknown>;
  transaction: Record<string, unknown>;
  receipt: Record<string, unknown>;
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  rawResponsePath: string;
  rawResponseSha256: string;
  persistedEvidence: { path: string; sha256: string };
  before: CaseState;
  after: CaseState;
  observedOutputUnits?: string;
  observedInputUnits?: string;
  participantAction: {
    kind: 'wrap' | 'approve' | 'swap';
    operationId: string;
    rawResponsePath: string;
    rawResponseSha256: string;
  };
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_v2_reverse_${label}_missing`);
  return value;
}

function uint(value: unknown, label: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && (/^0x[0-9a-f]+$/i.test(value) || UINT.test(value))) return BigInt(value);
  throw new Error(`task_v2_reverse_${label}_invalid`);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (record(value)) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function assert(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new Error(reason);
}

function poolFor(manifest: RuntimeManifest, feeTier: FeeTier): PoolIdentity {
  const pool = feeTier === 500 ? manifest.contracts.pool : manifest.contracts.pool3000;
  if (!pool || pool.fee !== feeTier || pool.token0.toLowerCase() !== manifest.contracts.weth.address.toLowerCase()
    || pool.token1.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || !ADDRESS.test(pool.address) || !HASH.test(pool.codeHash)) {
    throw new Error(`task_v2_reverse_fee${feeTier}_pool_identity_invalid`);
  }
  return { address: pool.address, codeHash: pool.codeHash, token0: pool.token0, token1: pool.token1, fee: pool.fee };
}

function profileTask(profile: Record<string, unknown>, taskId: 'M4' | 'H3'): Record<string, unknown> {
  const task = record(record(profile.tasks)?.[taskId]);
  if (!task) throw new Error(`task_v2_reverse_${taskId.toLowerCase()}_profile_missing`);
  return task;
}

async function loadDifficultyProfile(ctx: ProbeContext): Promise<{ profile: Record<string, unknown>; sha256: string }> {
  const bytes = await readFile(resolve(ctx.runtime.root, PROFILE_PATH));
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')) as unknown; }
  catch { throw new Error('task_v2_reverse_difficulty_profile_json_invalid'); }
  const profile = record(parsed);
  const compatibility = record(profile?.compatibility);
  const manifestPin = record(profile?.runtimeManifest);
  const boundary = record(profile?.measurementBoundary);
  if (!profile || profile.schemaVersion !== PROFILE_SCHEMA || profile.profileId !== PROFILE_ID
    || profile.classification !== 'candidate_case_inputs_not_capture_or_release'
    || profile.status !== 'source_profile_candidate_unactivated'
    || compatibility?.defaultProfile !== 'legacy' || compatibility.legacyCapturesAreImmutable !== true
    || compatibility.v2RequiresExplicitSelection !== true
    || manifestPin?.path !== 'infrastructure/benchmark-environment/manifest.json'
    || typeof manifestPin.sha256 !== 'string' || manifestPin.sha256.toLowerCase() !== ctx.runtime.manifestSha256.toLowerCase()
    || boundary?.approvalStatus !== 'not claimed'
    || boundary.releaseReadiness !== 'blocked_until_fresh_capture_and_release_review') {
    throw new Error('task_v2_reverse_difficulty_profile_pin_or_classification_mismatch');
  }
  return { profile, sha256 };
}

function validateProvidedDifficultyProfile(ctx: ProbeContext, source: ReverseSwapProfileSource): ReverseSwapProfileSource {
  const profile = source.profile;
  const compatibility = record(profile.compatibility);
  const manifestPin = record(profile.runtimeManifest);
  const boundary = record(profile.measurementBoundary);
  if (source.path !== PROFILE_PATH || !SHA256.test(source.sha256)
    || profile.schemaVersion !== PROFILE_SCHEMA || profile.profileId !== PROFILE_ID
    || profile.classification !== 'candidate_case_inputs_not_capture_or_release'
    || profile.status !== 'source_profile_candidate_unactivated'
    || compatibility?.defaultProfile !== 'legacy' || compatibility.legacyCapturesAreImmutable !== true
    || compatibility.v2RequiresExplicitSelection !== true
    || manifestPin?.path !== 'infrastructure/benchmark-environment/manifest.json'
    || typeof manifestPin.sha256 !== 'string' || manifestPin.sha256.toLowerCase() !== ctx.runtime.manifestSha256.toLowerCase()
    || boundary?.approvalStatus !== 'not claimed'
    || boundary.releaseReadiness !== 'blocked_until_fresh_capture_and_release_review') {
    throw new Error('task_v2_reverse_difficulty_profile_pin_or_classification_mismatch');
  }
  return source;
}

export function resolveM4InputUnits(profile: Record<string, unknown>, mode: DifficultyMode): string {
  const task = profileTask(profile, 'M4');
  const modes = record(task.modes);
  const values = record(modes?.[mode]);
  const expected = ['wrap', 'approve:exact-input', 'swap:WETH-to-USDC'];
  if (task.countedParticipantActions !== 3 || canonicalJson(task.participantActionPlan) !== canonicalJson(expected)
    || task.initialWethUnits !== '0' || task.inputAssetId !== 'WETH' || task.outputAssetId !== 'USDC'
    || task.finalAllowanceUnits !== '0' || task.feeTier !== 3000
    || task.cleanupPolicy !== 'exact_approval_may_be_consumed_by_swap_no_unnecessary_revoke') {
    throw new Error('task_v2_reverse_m4_profile_shape_invalid');
  }
  const amount = values?.exactInputUnits;
  if (typeof amount !== 'string' || !UINT.test(amount) || BigInt(amount) <= 0n) {
    throw new Error(`task_v2_reverse_m4_${mode}_profile_input_invalid`);
  }
  return amount;
}

export function resolveH3InputUnits(profile: Record<string, unknown>): string {
  const task = profileTask(profile, 'H3');
  const expected = [
    'inspect_offer', 'pay:route-reference', 'retrieve:route-reference',
    'wrap', 'approve:exact-input', 'swap:reference-selected-route',
  ];
  if (task.rankedOnly !== true || task.countedParticipantActions !== 6
    || canonicalJson(task.participantActionPlan) !== canonicalJson(expected)
    || task.referenceResourceId !== 'bef-market-state-brief-v1'
    || task.referenceOfferId !== 'market-brief-standard' || task.initialWethUnits !== '0'
    || task.inputAssetId !== 'WETH' || task.outputAssetId !== 'USDC'
    || task.routePolicy !== 'authenticated_delivered_reference_selects_one_of_release_pinned_routes') {
    throw new Error('task_v2_reverse_h3_profile_shape_invalid');
  }
  const amount = task.exactInputUnits;
  if (typeof amount !== 'string' || !UINT.test(amount) || BigInt(amount) <= 0n) {
    throw new Error('task_v2_reverse_h3_profile_input_invalid');
  }
  return amount;
}

/** Convert a measured WETH-denominated amount using the manifest's fixed ratio. */
export function convertEthWeiToUsdcUnits(ethWei: string, numerator: string, denominator: string): string {
  if (!UINT.test(ethWei) || !UINT.test(numerator) || !UINT.test(denominator) || BigInt(denominator) <= 0n) {
    throw new Error('task_v2_reverse_wei_to_usdc_rate_invalid');
  }
  return (BigInt(ethWei) * BigInt(numerator) / BigInt(denominator)).toString();
}

export function convertWethWeiToUsdcUnits(wethWei: string, numerator: string, denominator: string): string {
  return convertEthWeiToUsdcUnits(wethWei, numerator, denominator);
}

/** Charge is first measured in WETH wei, then converted to 6-decimal USDC units. */
export function measureDexFee(inputWethWei: string, feeTier: FeeTier, rateNumerator: string, rateDenominator: string): {
  feeWethWei: string; feeUsdcUnits: string;
} {
  if (!UINT.test(inputWethWei) || BigInt(inputWethWei) <= 0n) throw new Error('task_v2_reverse_dex_fee_input_invalid');
  const feeWethWei = ((BigInt(inputWethWei) * BigInt(feeTier) + 999_999n) / 1_000_000n).toString();
  return { feeWethWei, feeUsdcUnits: convertWethWeiToUsdcUnits(feeWethWei, rateNumerator, rateDenominator) };
}

export function resolveH3FeeTier(routeCode: unknown): FeeTier {
  if (routeCode === 'baseline') return 500;
  if (routeCode === 'alternative') return 3000;
  throw new Error('task_v2_reverse_h3_delivered_route_code_not_permitted');
}

export function validateH3SettlementBeforeTrade(
  receipt: SplitPaymentCapture['settlementReceipt'],
  expectedTransactionHash: string,
  beforeTradeBlock: string,
): string {
  const paidBlock = uint(receipt.blockNumber, 'h3_paid_receipt_block');
  const beforeTrade = uint(beforeTradeBlock, 'h3_before_trade_block');
  assert(receipt.status.toLowerCase() === '0x1'
    && HASH.test(receipt.blockHash) && HASH.test(receipt.transactionHash)
    && receipt.transactionHash.toLowerCase() === expectedTransactionHash.toLowerCase()
    && paidBlock <= beforeTrade,
  'task_v2_reverse_h3_paid_receipt_before_trade_invalid');
  return paidBlock.toString();
}

export function validateH3SettlementChronology(
  receipt: SplitPaymentCapture['settlementReceipt'],
  expectedTransactionHash: string,
  beforeTradeBlock: string,
  wrapReceiptBlock: string,
): string {
  const paidBlock = BigInt(validateH3SettlementBeforeTrade(receipt, expectedTransactionHash, beforeTradeBlock));
  const wrapBlock = uint(wrapReceiptBlock, 'h3_wrap_receipt_block');
  assert(paidBlock < wrapBlock, 'task_v2_reverse_h3_paid_reference_to_wrap_chronology_invalid');
  return paidBlock.toString();
}

export function measureAggregateGasUsdcUnits(gasCostsWei: readonly string[], numerator: string, denominator: string): string {
  if (gasCostsWei.some((value) => !UINT.test(value))) throw new Error('task_v2_reverse_gas_cost_invalid');
  const total = gasCostsWei.reduce((sum, value) => sum + BigInt(value), 0n);
  return convertEthWeiToUsdcUnits(total.toString(), numerator, denominator);
}

async function queryQuote(ctx: ProbeContext, session: GenerationSession, amountInUnits: string, feeTier: FeeTier, caseName: CaseName): Promise<QuotePlan> {
  const manifest = ctx.runtime.manifest;
  const pool = poolFor(manifest, feeTier);
  const amount = BigInt(amountInUnits);
  if (!UINT.test(amountInUnits) || amount <= 0n || amount > BigInt(manifest.swap.maxAmountIn)
    || !Number.isSafeInteger(manifest.swap.maxSlippageBps) || manifest.swap.maxSlippageBps < 0
    || manifest.swap.maxSlippageBps >= 10_000) {
    throw new Error(`task_v2_reverse_${caseName}_quote_input_or_slippage_invalid`);
  }
  const label = `${caseName}-fee${feeTier}`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `${label}-planning-public-quote`, method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/quote?inputAssetId=WETH&feeTier=${feeTier}&amountInUnits=${encodeURIComponent(amountInUnits)}`),
    headers: {
      authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': randomUUID(), 'content-type': 'application/json',
    },
    operationId: null, variantId: VARIANT_ID, includeRawResponseBytes: true,
  });
  const body = record(response.body);
  const quote = record(body?.quote);
  assert(response.status === 200 && body && quote, `task_v2_reverse_${label}_public_quote_unavailable`);
  assert(body.envId === session.envId && body.generationId === session.generationId
    && body.route === 'uniswap-v3-exactInputSingle'
    && body.inputAssetId === 'WETH' && body.outputAssetId === 'USDC' && body.fee === feeTier
    && String(body.tokenIn).toLowerCase() === manifest.contracts.weth.address.toLowerCase()
    && String(body.tokenOut).toLowerCase() === manifest.contracts.usdc.address.toLowerCase()
    && String(body.poolAddress).toLowerCase() === pool.address.toLowerCase()
    && String(body.poolCodeHash).toLowerCase() === pool.codeHash.toLowerCase()
    && body.quoteStatus === 'observed' && String(body.requestedAmountInUnits) === amountInUnits,
  `task_v2_reverse_${label}_public_quote_identity_invalid`);
  assert(quote.inputAssetId === 'WETH' && quote.outputAssetId === 'USDC' && quote.feeTier === feeTier
    && String(quote.poolAddress).toLowerCase() === pool.address.toLowerCase()
    && String(quote.poolCodeHash).toLowerCase() === pool.codeHash.toLowerCase()
    && String(quote.amountInUnits) === amountInUnits && String(quote.blockNumber) === String(body.blockNumber)
    && UINT.test(String(quote.amountOutUnits)) && BigInt(String(quote.amountOutUnits)) > 0n
    && UINT.test(String(body.blockNumber)),
  `task_v2_reverse_${label}_public_quote_payload_invalid`);

  const blockNumber = String(body.blockNumber);
  const blockTag = `0x${BigInt(blockNumber).toString(16)}`;
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: blockTag,
    operationId: null, variantId: VARIANT_ID, label: `${label}-planning-quote-block-identity`,
  });
  assert(BigInt(block.number) === BigInt(blockNumber), `task_v2_reverse_${label}_quote_block_mismatch`);
  const quoteData = encodeFunctionData({
    abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle',
    args: [{ tokenIn: manifest.contracts.weth.address as Address, tokenOut: manifest.contracts.usdc.address as Address,
      amountIn: amount, fee: feeTier, sqrtPriceLimitX96: 0n }],
  });
  const independent = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_call', params: [{ to: manifest.contracts.quoterV2.address, data: quoteData }, blockTag],
    requestedBlock: blockTag, operationId: null, variantId: VARIANT_ID, label: `${label}-planning-independent-quoter-v2`,
  });
  assert(typeof independent.result === 'string' && /^0x[0-9a-f]{256}$/i.test(independent.result),
    `task_v2_reverse_${label}_independent_quote_invalid`);
  const decoded = decodeFunctionResult({ abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', data: independent.result as Hex });
  const output = BigInt(String(quote.amountOutUnits));
  assert(decoded[0] === output, `task_v2_reverse_${label}_independent_quote_mismatch`);
  const minimum = output * BigInt(10_000 - manifest.swap.maxSlippageBps) / 10_000n;
  assert(minimum > 0n && minimum <= output, `task_v2_reverse_${label}_minimum_output_invalid`);

  const rawQuotePath = `task-v2/preflight/${label}-public-quote.raw.json`;
  await ctx.evidence.writeRawJson(rawQuotePath, response.rawBody, 'actual-tool-http-raw-response');
  const rawQuote = ctx.evidence.artifacts.at(-1);
  assert(rawQuote?.path === rawQuotePath, `task_v2_reverse_${label}_raw_quote_missing`);

  const quoteArtifactPath = `task-v2/preflight/${label}-public-quote.json`;
  await ctx.evidence.writeObservation(quoteArtifactPath, `${label}-verified-planning-quote`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'actual-tool-http-and-local-chain-readonly-proxy',
    operationId: null, variantId: VARIANT_ID,
    profileSource: { path: PROFILE_PATH }, environment: { envId: session.envId, generationId: session.generationId },
    request: { inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits, feeTier },
    publicQuote: body,
    rawPublicQuote: { path: rawQuote.path, sha256: rawQuote.sha256 },
    independentQuoterV2: {
      address: manifest.contracts.quoterV2.address, blockNumber, blockHash: block.hash.toLowerCase(),
      calldata: quoteData, rawResult: independent.result, outputUnits: output.toString(),
      sqrtPriceX96After: decoded[1].toString(), initializedTicksCrossed: decoded[2].toString(), gasEstimate: decoded[3].toString(),
    },
    releasePinnedRoute: { feeTier, poolAddress: pool.address.toLowerCase(), poolCodeHash: pool.codeHash.toLowerCase() },
    minimumOutputUnits: minimum.toString(), maxSlippageBps: manifest.swap.maxSlippageBps,
    countedParticipantAction: false,
  });
  const quoteArtifact = ctx.evidence.artifacts.at(-1);
  assert(quoteArtifact?.path === quoteArtifactPath, `task_v2_reverse_${label}_quote_artifact_missing`);
  const planPath = `task-v2/preflight/${label}-immutable-plan.json`;
  await ctx.evidence.writeObservation(planPath, `${label}-immutable-quote-plan`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId: null, variantId: VARIANT_ID, countedParticipantAction: false,
    environment: { envId: session.envId, planningGenerationId: session.generationId },
    profileInputUnits: amountInUnits,
    route: { inputAssetId: 'WETH', outputAssetId: 'USDC', feeTier, poolAddress: pool.address.toLowerCase(), poolCodeHash: pool.codeHash.toLowerCase() },
    quoteBlock: { number: blockNumber, hash: block.hash.toLowerCase() },
    exactOutputUnits: output.toString(), minimumOutputUnits: minimum.toString(),
    maxSlippageBps: manifest.swap.maxSlippageBps,
    quoteEvidence: { path: quoteArtifact.path, sha256: quoteArtifact.sha256 },
    rawPublicQuote: { path: rawQuote.path, sha256: rawQuote.sha256 },
    classification: 'preparation_evidence_not_counted_participant_action_or_release_pin',
  });
  const planArtifact = ctx.evidence.artifacts.at(-1);
  assert(planArtifact?.path === planPath, `task_v2_reverse_${label}_quote_plan_artifact_missing`);
  return {
    feeTier, poolAddress: pool.address.toLowerCase(), poolCodeHash: pool.codeHash.toLowerCase(),
    inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits, amountOutUnits: output.toString(),
    minimumOutputUnits: minimum.toString(), slippageBps: manifest.swap.maxSlippageBps,
    blockNumber, blockHash: block.hash.toLowerCase(), independentQuoterV2OutputUnits: decoded[0].toString(),
    publicQuoteArtifact: { path: quoteArtifact.path, sha256: quoteArtifact.sha256 },
    planArtifact: { path: planArtifact.path, sha256: planArtifact.sha256 },
  };
}

const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
]);

async function readCaseStateAt(ctx: ProbeContext, session: GenerationSession, blockTag: string, blockHash: string, operationId: string | null, label: string, poolFeeTier: FeeTier = 3000): Promise<CaseState> {
  const state = await readCaseState(ctx, { session, blockTag, blockHash, operationId, variantId: VARIANT_ID, label });
  const pool = poolFor(ctx.runtime.manifest, poolFeeTier);
  const [poolWethUnits, poolUsdcUnits] = await Promise.all([
    readTokenValue(ctx, { token: ctx.runtime.manifest.contracts.weth.address, functionName: 'balanceOf', args: [pool.address], blockTag, operationId, variantId: VARIANT_ID, label: `${label}-pool-weth` }),
    readTokenValue(ctx, { token: ctx.runtime.manifest.contracts.usdc.address, functionName: 'balanceOf', args: [pool.address], blockTag, operationId, variantId: VARIANT_ID, label: `${label}-pool-usdc` }),
  ]);
  return {
    blockNumber: String(state.blockNumber), blockHash: String(state.blockHash).toLowerCase(),
    payerAddress: String(state.payerAddress).toLowerCase(), payerNativeEthWei: String(state.payerNativeEthWei),
    payerWethUnits: String(state.payerWethUnits), payerUsdcUnits: String(state.payerUsdcUnits),
    wethRouterAllowanceUnits: String(state.wethRouterAllowanceUnits), usdcRouterAllowanceUnits: String(state.usdcRouterAllowanceUnits),
    poolWethUnits, poolUsdcUnits,
  };
}

async function latestCaseState(ctx: ProbeContext, session: GenerationSession, label: string, poolFeeTier: FeeTier = 3000): Promise<CaseState> {
  const block = await latestBlock(ctx, null, VARIANT_ID, label);
  return readCaseStateAt(ctx, session, block.tag, block.hash, null, label, poolFeeTier);
}

function assertZeroAllowances(state: CaseState, label: string): void {
  assert(state.wethRouterAllowanceUnits === '0' && state.usdcRouterAllowanceUnits === '0',
    `task_v2_reverse_${label}_initial_allowance_nonzero`);
}

function expectedSelectedAction(kind: 'wrap' | 'approve' | 'swap', body: Record<string, string>, feeTier?: FeeTier): Record<string, unknown> {
  if (kind === 'wrap') return { kind, amountWei: requiredString(body.amountWei, 'wrap_amount'), gasLimit: requiredString(body.gasLimit, 'wrap_gas_limit') };
  if (kind === 'approve') return { kind, tokenAssetId: 'WETH', amountUnits: requiredString(body.amountUnits, 'approval_amount'), gasLimit: requiredString(body.gasLimit, 'approval_gas_limit') };
  return {
    kind, inputAssetId: 'WETH', outputAssetId: 'USDC', feeTier,
    amountInUnits: requiredString(body.amountInUnits, 'swap_amount'),
    amountOutMinimumUnits: requiredString(body.amountOutMinimumUnits, 'swap_minimum'),
    recipient: requiredString(body.recipient, 'swap_recipient').toLowerCase(),
    gasLimit: requiredString(body.gasLimit, 'swap_gas_limit'),
  };
}

function transactionIntent(ctx: ProbeContext, session: GenerationSession, kind: 'wrap' | 'approve' | 'swap', body: Record<string, string>, feeTier?: FeeTier): {
  to: string; valueWei: string; input: Hex; expectedAction: Record<string, unknown>; principalAsset: string | null; principalUnits: string;
} {
  const manifest = ctx.runtime.manifest;
  if (kind === 'wrap') {
    const amountWei = requiredString(body.amountWei, 'wrap_amount');
    return {
    to: manifest.contracts.weth.address, valueWei: amountWei,
    input: encodeFunctionData({ abi: WETH_ABI, functionName: 'deposit' }),
    expectedAction: expectedSelectedAction(kind, body), principalAsset: 'ETH', principalUnits: amountWei,
    };
  }
  if (kind === 'approve') {
    const amountUnits = requiredString(body.amountUnits, 'approval_amount');
    return {
    to: manifest.contracts.weth.address, valueWei: '0',
    input: encodeFunctionData({ abi: APPROVE_ABI, functionName: 'approve', args: [manifest.contracts.swapRouter02.address as Address, BigInt(amountUnits)] }),
    expectedAction: expectedSelectedAction(kind, body), principalAsset: null, principalUnits: '0',
    };
  }
  if (!feeTier) throw new Error('task_v2_reverse_swap_fee_tier_missing');
  const amountInUnits = requiredString(body.amountInUnits, 'swap_amount');
  const amountOutMinimumUnits = requiredString(body.amountOutMinimumUnits, 'swap_minimum');
  return {
    to: manifest.contracts.swapRouter02.address, valueWei: '0',
    input: encodeFunctionData({
      abi: SWAP_ROUTER_ABI, functionName: 'exactInputSingle',
      args: [{ tokenIn: manifest.contracts.weth.address as Address, tokenOut: manifest.contracts.usdc.address as Address,
        fee: feeTier, recipient: session.payerAddress as Address, amountIn: BigInt(amountInUnits),
        amountOutMinimum: BigInt(amountOutMinimumUnits), sqrtPriceLimitX96: 0n }],
    }),
    expectedAction: expectedSelectedAction(kind, body, feeTier), principalAsset: 'WETH', principalUnits: amountInUnits,
  };
}

async function observeActionDatabase(ctx: ProbeContext, session: GenerationSession, input: {
  kind: 'wrap' | 'approve' | 'swap'; operationId: string; transactionHash: string; expectedAction: Record<string, unknown>;
  to: string; input: string; valueWei: string; nonce: string; gasLimit: string; principalAsset: string | null; principalUnits: string;
  gasUsed: string; effectiveGasPriceWei: string; gasCostWei: string; feeTier?: FeeTier;
}): Promise<{ path: string; sha256: string }> {
  const pool = new Pool({
    connectionString: ctx.env.databaseObserverUrl, max: 1, connectionTimeoutMillis: 5_000,
    statement_timeout: 5_000, query_timeout: 8_000, application_name: 'web-agent-bench-bef-v2-reverse-readonly',
  });
  const client = await pool.connect();
  try {
    await client.query('BEGIN READ ONLY');
    const [role, mode, operation, execution, cost, events] = await Promise.all([
      client.query('SELECT current_user AS role_name'), client.query('SHOW transaction_read_only'),
      client.query('SELECT operation_id::text,env_id,generation_id::text,participant_id,operation_kind,status,transaction_hash,receipt_status FROM bef_operation WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid', [session.envId, session.generationId, input.operationId]),
      client.query('SELECT operation_id::text,action_kind,selected_action_json,transaction_intent_json,transaction_hash,outcome,measurement_json FROM bef_selected_execution WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid', [session.envId, session.generationId, input.operationId]),
      client.query('SELECT * FROM bef_transaction_cost WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid', [session.envId, session.generationId, input.operationId]),
      client.query('SELECT event_sequence::text,event_kind,transaction_hash,event_json FROM bef_selected_execution_event WHERE env_id=$1 AND generation_id=$2::uuid AND operation_id=$3::uuid ORDER BY event_sequence', [session.envId, session.generationId, input.operationId]),
    ]);
    const databaseRole = String(role.rows[0]?.role_name ?? '');
    const transactionReadOnly = String(mode.rows[0]?.transaction_read_only ?? '');
    const op = record(operation.rows[0]);
    const exec = record(execution.rows[0]);
    const costRow = record(cost.rows[0]);
    const storedAction = record(typeof exec?.selected_action_json === 'string' ? JSON.parse(exec.selected_action_json) : exec?.selected_action_json);
    const intent = record(typeof exec?.transaction_intent_json === 'string' ? JSON.parse(exec.transaction_intent_json) : exec?.transaction_intent_json);
    const evidence = record(typeof costRow?.receipt_evidence_json === 'string' ? JSON.parse(costRow.receipt_evidence_json) : costRow?.receipt_evidence_json);
    const persistedReceipt = record(evidence?.receipt);
    assert(databaseRole === ctx.database.databaseRole && transactionReadOnly === 'on', 'task_v2_reverse_database_not_readonly');
    assert(op && exec && costRow && operation.rows.length === 1 && execution.rows.length === 1 && cost.rows.length === 1,
      `task_v2_reverse_${input.kind}_database_rows_missing`);
    assert(op.operation_id === input.operationId && op.env_id === session.envId && op.generation_id === session.generationId
      && op.participant_id === session.participantId && op.operation_kind === input.kind
      && op.status === 'settled' && op.receipt_status === 'success'
      && String(op.transaction_hash).toLowerCase() === input.transactionHash.toLowerCase(),
    `task_v2_reverse_${input.kind}_database_operation_mismatch`);
    assert(exec.operation_id === input.operationId && exec.action_kind === input.kind && exec.outcome === 'success'
      && String(exec.transaction_hash).toLowerCase() === input.transactionHash.toLowerCase()
      && canonicalJson(storedAction) === canonicalJson(input.expectedAction),
    `task_v2_reverse_${input.kind}_database_selected_action_mismatch`);
    assert(intent && String(intent.hash).toLowerCase() === input.transactionHash.toLowerCase()
      && String(intent.from).toLowerCase() === session.payerAddress.toLowerCase()
      && String(intent.to).toLowerCase() === input.to.toLowerCase()
      && String(intent.input).toLowerCase() === input.input.toLowerCase()
      && uint(intent.valueWei, `${input.kind}_db_value`).toString() === input.valueWei
      && uint(intent.nonce, `${input.kind}_db_nonce`).toString() === input.nonce
      && uint(intent.gasLimit, `${input.kind}_db_gas_limit`).toString() === input.gasLimit,
    `task_v2_reverse_${input.kind}_database_intent_mismatch`);
    assert(costRow.receipt_status === 'success' && String(costRow.transaction_hash).toLowerCase() === input.transactionHash.toLowerCase()
      && String(costRow.payer_address).toLowerCase() === session.payerAddress.toLowerCase()
      && costRow.payer_role === 'participant' && String(costRow.transaction_from).toLowerCase() === session.payerAddress.toLowerCase()
      && String(costRow.receipt_from).toLowerCase() === session.payerAddress.toLowerCase()
      && String(costRow.selected_principal_asset ?? '') === String(input.principalAsset ?? '')
      && String(costRow.selected_principal_units) === input.principalUnits
      && String(costRow.observed_principal_units) === input.principalUnits
      && String(costRow.gas_used) === input.gasUsed
      && String(costRow.effective_gas_price_wei) === input.effectiveGasPriceWei
      && String(costRow.gas_cost_wei) === input.gasCostWei
      && persistedReceipt && String(persistedReceipt.transactionHash).toLowerCase() === input.transactionHash.toLowerCase()
      && persistedReceipt.status === 'success' && String(persistedReceipt.gasUsed) === input.gasUsed
      && String(persistedReceipt.effectiveGasPriceWei) === input.effectiveGasPriceWei,
    `task_v2_reverse_${input.kind}_database_receipt_or_cost_mismatch`);
    if (input.kind === 'swap') {
      const measurement = record(typeof exec.measurement_json === 'string' ? JSON.parse(exec.measurement_json) : exec.measurement_json);
      const selected = record(measurement?.selectedAction);
      const expectedPool = poolFor(ctx.runtime.manifest, input.feeTier!);
      const routeMatches = input.feeTier === 500
        ? selected?.route === 'uniswap-v3-exactInputSingle' && selected.fee === 500
          && String(selected.tokenIn).toLowerCase() === ctx.runtime.manifest.contracts.weth.address.toLowerCase()
          && String(selected.tokenOut).toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase()
          && String(selected.amountInWei) === String(input.expectedAction.amountInUnits)
          && String(selected.amountOutMinimumUsdcUnits) === String(input.expectedAction.amountOutMinimumUnits)
          && String(selected.recipient).toLowerCase() === String(input.expectedAction.recipient).toLowerCase()
          && String(selected.gasLimit) === input.gasLimit
        : selected?.route === 'uniswap-v3-exactInputSingle' && selected.fee === 3000
          && String(selected.inputAssetId) === 'WETH' && String(selected.outputAssetId) === 'USDC'
          && String(selected.poolAddress).toLowerCase() === expectedPool.address.toLowerCase()
          && String(selected.poolCodeHash).toLowerCase() === expectedPool.codeHash.toLowerCase()
          && String(selected.amountInUnits) === String(input.expectedAction.amountInUnits)
          && String(selected.amountOutMinimumUnits) === String(input.expectedAction.amountOutMinimumUnits)
          && String(selected.recipient).toLowerCase() === String(input.expectedAction.recipient).toLowerCase()
          && String(selected.gasLimit) === input.gasLimit;
      assert(selected && routeMatches,
      'task_v2_reverse_swap_database_route_mismatch');
    }
    const expectedModeledFee = convertEthWeiToUsdcUnits(input.gasCostWei,
      ctx.runtime.manifest.feePolicy.ethUsdcRateNumerator, ctx.runtime.manifest.feePolicy.ethUsdcRateDenominator);
    assert(String(costRow.modeled_gas_fee_usdc_units) === expectedModeledFee,
      `task_v2_reverse_${input.kind}_database_modeled_gas_fee_mismatch`);
    const eventRows = events.rows as Array<Record<string, unknown>>;
    const eventKinds = eventRows.map((row) => row.event_kind);
    const expectedKinds = ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'];
    assert(expectedKinds.every((kind) => eventKinds.filter((candidate) => candidate === kind).length === 1)
      && expectedKinds.map((kind) => eventKinds.indexOf(kind)).every((position, index, positions) => index === 0 || position > positions[index - 1]!)
      && String(eventRows.find((row) => row.event_kind === 'receipt_finalized')?.transaction_hash).toLowerCase() === input.transactionHash.toLowerCase(),
    `task_v2_reverse_${input.kind}_database_event_order_invalid`);
    const rows = { operation: op, selectedExecution: exec, transactionCost: costRow, events: eventRows };
    const path = `db/task-v2-${input.kind}-${input.operationId}.json`;
    await ctx.evidence.writeObservation(path, `task-v2-${input.kind}-${input.operationId}-persisted`, {
      schemaVersion: 'bef-db-observation/v1', boundary: 'readonly-database', operationId: input.operationId,
      variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId, readOnly: true,
      databaseRole, transactionReadOnly, queryName: 'selected-action-transaction-cost-and-event-proof',
      rows: sanitizeValue(rows, ctx.secretValues),
    });
    const artifact = ctx.evidence.artifacts.at(-1);
    assert(artifact?.path === path, 'task_v2_reverse_database_evidence_artifact_missing');
    await client.query('ROLLBACK');
    return { path: artifact.path, sha256: artifact.sha256 };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (error instanceof Error && /^task_v2_reverse_[a-z0-9_]+$/.test(error.message)) throw error;
    throw new Error(`task_v2_reverse_${input.kind}_database_observation_unavailable`);
  } finally {
    client.release();
    await pool.end();
  }
}

async function recordSelectedAction(ctx: ProbeContext, session: GenerationSession, input: {
  kind: 'wrap' | 'approve' | 'swap'; body: Record<string, string>; feeTier?: FeeTier; poolFeeTier: FeeTier; label: string;
}): Promise<CapturedAction> {
  const { kind, body, feeTier, label } = input;
  const manifest = ctx.runtime.manifest;
  const before = await latestCaseState(ctx, session, `${label}-before`, input.poolFeeTier);
  const expected = transactionIntent(ctx, session, kind, body, feeTier);
  const idempotencyKey = randomUUID();
  const observationId = `${label}-selected-action`;
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/${kind}`),
    headers: {
      authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey, 'content-type': 'application/json',
    },
    body, operationId: null, variantId: VARIANT_ID,
    resolveOperationId: async (_status, value) => typeof record(value)?.operationId === 'string' ? String(record(value)!.operationId) : null,
  });
  const bodyRecord = record(response.body);
  const operationId = response.operationId ?? (typeof bodyRecord?.operationId === 'string' ? bodyRecord.operationId : null);
  assert(response.status === 200 && bodyRecord?.outcome === 'success' && operationId && UUID.test(operationId),
    `task_v2_reverse_${label}_action_http_failed_${response.status}`);
  const action = record(bodyRecord.selectedAction);
  const transaction = record(bodyRecord.transaction);
  const receiptBody = record(bodyRecord.receipt);
  const fee = record(bodyRecord.fee);
  assert(action && transaction && receiptBody, `task_v2_reverse_${label}_action_measurement_missing`);
  const expectedAction = expected.expectedAction;
  if (kind === 'swap') {
    const pool = poolFor(manifest, feeTier!);
    const routeActionMatches = feeTier === 500
      ? action.kind === 'swap' && action.route === 'uniswap-v3-exactInputSingle' && action.fee === 500
        && String(action.amountInWei) === body.amountInUnits
        && String(action.amountOutMinimumUsdcUnits) === body.amountOutMinimumUnits
        && String(action.tokenIn).toLowerCase() === manifest.contracts.weth.address.toLowerCase()
        && String(action.tokenOut).toLowerCase() === manifest.contracts.usdc.address.toLowerCase()
      : action.kind === 'swap' && action.inputAssetId === 'WETH' && action.outputAssetId === 'USDC'
        && action.fee === feeTier && String(action.amountInUnits) === body.amountInUnits
        && String(action.amountOutMinimumUnits) === body.amountOutMinimumUnits
        && String(action.poolAddress).toLowerCase() === pool.address.toLowerCase()
        && String(action.poolCodeHash).toLowerCase() === pool.codeHash.toLowerCase();
    assert(routeActionMatches
      && String(action.recipient).toLowerCase() === session.payerAddress.toLowerCase()
      && String(action.gasLimit) === body.gasLimit
      && String(action.router).toLowerCase() === manifest.contracts.swapRouter02.address.toLowerCase()
      && (feeTier === 500 || String(action.tokenIn).toLowerCase() === manifest.contracts.weth.address.toLowerCase())
      && (feeTier === 500 || String(action.tokenOut).toLowerCase() === manifest.contracts.usdc.address.toLowerCase()),
    `task_v2_reverse_${label}_selected_swap_not_bound_to_route`);
  } else {
    for (const [field, value] of Object.entries(expectedAction)) {
      if (field === 'kind') continue;
      assert(String(action[field]) === String(value), `task_v2_reverse_${label}_selected_${kind}_field_mismatch`);
    }
    if (kind === 'approve') assert(action.tokenAssetId === 'WETH'
      && String(action.token).toLowerCase() === manifest.contracts.weth.address.toLowerCase()
      && String(action.spender).toLowerCase() === manifest.contracts.swapRouter02.address.toLowerCase(),
    `task_v2_reverse_${label}_selected_approval_route_mismatch`);
  }
  const txHash = requiredString(transaction.hash, `${label}_transaction_hash`);
  assert(HASH.test(txHash) && String(receiptBody.transactionHash).toLowerCase() === txHash.toLowerCase()
    && String(transaction.from).toLowerCase() === session.payerAddress.toLowerCase()
    && String(transaction.to).toLowerCase() === expected.to.toLowerCase()
    && String(transaction.input).toLowerCase() === expected.input.toLowerCase()
    && uint(transaction.valueWei, `${label}_transaction_value`).toString() === expected.valueWei
    && BigInt(String(transaction.chainId)) === BigInt(manifest.local.chainId)
    && uint(transaction.gasLimit, `${label}_transaction_gas_limit`).toString() === body.gasLimit,
  `task_v2_reverse_${label}_transaction_intent_http_binding_invalid`);
  const nonce = uint(transaction.nonce, `${label}_transaction_nonce`).toString();
  const rawResponsePath = `task-v2/responses/${label}-${operationId}.json`;
  await ctx.evidence.writeRawJson(rawResponsePath, response.rawBody, 'actual-tool-http-raw-response');
  const rawResponse = ctx.evidence.artifacts.at(-1);
  assert(rawResponse?.path === rawResponsePath, `task_v2_reverse_${label}_raw_response_missing`);

  const checked = await ctx.rpc.call<Record<string, unknown>>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [txHash], operationId, variantId: VARIANT_ID,
    label: `${label}-transaction-binding`,
    selectedExecutionTransaction: {
      environmentId: session.envId, operationId, variantId: VARIANT_ID,
      kind, transactionHash: txHash, expectedFrom: session.payerAddress, expectedTo: expected.to,
      expectedValueWei: expected.valueWei, expectedChainId: String(manifest.local.chainId), expectedNonce: nonce,
      expectedGas: body.gasLimit, expectedInput: expected.input,
    } satisfies SelectedExecutionTransactionEvidence,
  });
  assert(record(checked.result)?.input?.toString().toLowerCase() === expected.input.toLowerCase(),
    `task_v2_reverse_${label}_onchain_transaction_mismatch`);
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash: txHash,
    operationId, variantId: VARIANT_ID, label: `${label}-receipt`,
  });
  assert(receipt.status.toLowerCase() === '0x1' && receipt.transactionHash.toLowerCase() === txHash.toLowerCase()
    && receipt.from.toLowerCase() === session.payerAddress.toLowerCase() && receipt.to?.toLowerCase() === expected.to.toLowerCase(),
  `task_v2_reverse_${label}_receipt_identity_invalid`);
  const gasUsed = uint(receipt.gasUsed, `${label}_gas_used`);
  const effectiveGasPriceWei = uint(receipt.effectiveGasPrice, `${label}_effective_gas_price`);
  const gasCostWei = gasUsed * effectiveGasPriceWei;
  assert(uint(receiptBody.gasUsed, `${label}_http_gas_used`) === gasUsed
    && uint(receiptBody.effectiveGasPrice, `${label}_http_effective_gas_price`) === effectiveGasPriceWei
    && uint(receiptBody.gasCostWei, `${label}_http_gas_cost`) === gasCostWei
    && receiptBody.status === 'success'
    && fee && (fee.principalAsset ?? null) === expected.principalAsset
    && String(fee.selectedPrincipalUnits) === expected.principalUnits && String(fee.principalUnits) === expected.principalUnits,
  `task_v2_reverse_${label}_http_receipt_or_principal_mismatch`);
  const receiptTag = `0x${BigInt(receipt.blockNumber).toString(16)}`;
  const receiptBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: receiptTag,
    operationId, variantId: VARIANT_ID, label: `${label}-receipt-block-identity`,
  });
  assert(BigInt(receiptBlock.number) === BigInt(receipt.blockNumber)
    && receiptBlock.hash.toLowerCase() === receipt.blockHash.toLowerCase(), `task_v2_reverse_${label}_receipt_block_invalid`);
  const after = await readCaseStateAt(ctx, session, receiptTag, receipt.blockHash, operationId, `${label}-after`, input.poolFeeTier);
  const persistedEvidence = await observeActionDatabase(ctx, session, {
    kind, operationId, transactionHash: txHash, expectedAction, to: expected.to,
    input: expected.input, valueWei: expected.valueWei, nonce, gasLimit: requiredString(body.gasLimit, `${label}_gas_limit`),
    principalAsset: expected.principalAsset, principalUnits: expected.principalUnits,
    gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
    ...(feeTier === undefined ? {} : { feeTier }),
  });

  if (kind === 'wrap') {
    const amount = BigInt(requiredString(body.amountWei, `${label}_amount`));
    const deposits = receipt.logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()).flatMap((log) => {
      try {
        const decoded = decodeEventLog({ abi: WETH_ABI, eventName: 'Deposit', topics: log.topics as [`0x${string}`, ...`0x${string}`[]], data: log.data as Hex });
        const args = decoded.args as { dst: Address; wad: bigint };
        return args.dst.toLowerCase() === session.payerAddress.toLowerCase() && args.wad === amount ? [args] : [];
      } catch { return []; }
    });
    assert(deposits.length === 1 && BigInt(after.payerWethUnits) - BigInt(before.payerWethUnits) === amount
      && BigInt(before.payerNativeEthWei) - BigInt(after.payerNativeEthWei) === amount + gasCostWei
      && after.payerUsdcUnits === before.payerUsdcUnits && after.wethRouterAllowanceUnits === '0'
      && after.usdcRouterAllowanceUnits === '0' && after.poolWethUnits === before.poolWethUnits
      && after.poolUsdcUnits === before.poolUsdcUnits,
    `task_v2_reverse_${label}_wrap_effect_mismatch`);
  } else if (kind === 'approve') {
    const amount = BigInt(requiredString(body.amountUnits, `${label}_amount`));
    const approvalCount = receipt.logs.filter((log) => log.address.toLowerCase() === manifest.contracts.weth.address.toLowerCase()).flatMap((log) => {
      try {
        const decoded = decodeEventLog({ abi: APPROVAL_ABI, eventName: 'Approval', topics: log.topics as [`0x${string}`, ...`0x${string}`[]], data: log.data as Hex });
        const args = decoded.args as { owner: Address; spender: Address; value: bigint };
        return args.owner.toLowerCase() === session.payerAddress.toLowerCase()
          && args.spender.toLowerCase() === manifest.contracts.swapRouter02.address.toLowerCase() && args.value === amount ? [args] : [];
      } catch { return []; }
    }).length;
    assert(approvalCount === 1 && before.wethRouterAllowanceUnits === '0'
      && after.wethRouterAllowanceUnits === amount.toString() && after.usdcRouterAllowanceUnits === '0'
      && after.payerWethUnits === before.payerWethUnits && after.payerUsdcUnits === before.payerUsdcUnits
      && BigInt(before.payerNativeEthWei) - BigInt(after.payerNativeEthWei) === gasCostWei
      && after.poolWethUnits === before.poolWethUnits && after.poolUsdcUnits === before.poolUsdcUnits,
    `task_v2_reverse_${label}_approval_effect_mismatch`);
  } else {
    const amount = BigInt(requiredString(body.amountInUnits, `${label}_amount`));
    const pool = poolFor(manifest, feeTier!);
    const poolLogs = receipt.logs.filter((log) => log.address.toLowerCase() === pool.address.toLowerCase());
    assert(poolLogs.length === 1, `task_v2_reverse_${label}_pool_swap_event_count_invalid`);
    let output = 0n;
    try {
      const decoded = decodeEventLog({ abi: POOL_SWAP_ABI, eventName: 'Swap', topics: poolLogs[0]!.topics as [`0x${string}`, ...`0x${string}`[]], data: poolLogs[0]!.data as Hex });
      const args = decoded.args as { sender: Address; recipient: Address; amount0: bigint; amount1: bigint };
      assert(args.sender.toLowerCase() === manifest.contracts.swapRouter02.address.toLowerCase()
        && args.recipient.toLowerCase() === session.payerAddress.toLowerCase()
        && args.amount0 === amount && args.amount1 < 0n,
      `task_v2_reverse_${label}_pool_swap_direction_invalid`);
      output = -args.amount1;
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('task_v2_reverse_')) throw error;
      throw new Error(`task_v2_reverse_${label}_pool_swap_event_invalid`);
    }
    const minimum = BigInt(requiredString(body.amountOutMinimumUnits, `${label}_minimum`));
    const wethTransfers = transferEvents(receipt, manifest.contracts.weth.address).filter((entry) =>
      entry.from.toLowerCase() === session.payerAddress.toLowerCase() && entry.to.toLowerCase() === pool.address.toLowerCase() && entry.amount === amount);
    const usdcTransfers = transferEvents(receipt, manifest.contracts.usdc.address).filter((entry) =>
      entry.from.toLowerCase() === pool.address.toLowerCase() && entry.to.toLowerCase() === session.payerAddress.toLowerCase() && entry.amount === output);
    assert(output >= minimum && wethTransfers.length === 1 && usdcTransfers.length === 1
      && BigInt(before.payerWethUnits) - BigInt(after.payerWethUnits) === amount
      && BigInt(after.payerUsdcUnits) - BigInt(before.payerUsdcUnits) === output
      && BigInt(after.wethRouterAllowanceUnits) === BigInt(before.wethRouterAllowanceUnits) - amount
      && after.usdcRouterAllowanceUnits === before.usdcRouterAllowanceUnits
      && BigInt(after.poolWethUnits) - BigInt(before.poolWethUnits) === amount
      && BigInt(before.poolUsdcUnits) - BigInt(after.poolUsdcUnits) === output
      && BigInt(before.payerNativeEthWei) - BigInt(after.payerNativeEthWei) === gasCostWei,
    `task_v2_reverse_${label}_swap_effect_mismatch`);
    const idempotencyKeySha256 = createHash('sha256').update(idempotencyKey).digest('hex');
    ctx.operations.set(operationId, {
      operationId, kind, idempotencyKeyHash: idempotencyKeySha256,
      observedStatus: 'settled', transactionHash: txHash.toLowerCase(), receiptStatus: 'success',
    });
    return {
      kind, operationId, transactionHash: txHash.toLowerCase(), idempotencyKeySha256,
      selectedAction: action, transaction, receipt: { ...receiptBody, status: receipt.status, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash },
      gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
      rawResponsePath, rawResponseSha256: sha256Bytes(response.rawBody), persistedEvidence, before, after,
      observedOutputUnits: output.toString(), observedInputUnits: amount.toString(),
      participantAction: { kind, operationId, rawResponsePath, rawResponseSha256: sha256Bytes(response.rawBody) },
    };
  }
  const idempotencyKeySha256 = createHash('sha256').update(idempotencyKey).digest('hex');
  ctx.operations.set(operationId, {
    operationId, kind, idempotencyKeyHash: idempotencyKeySha256,
    observedStatus: 'settled', transactionHash: txHash.toLowerCase(), receiptStatus: 'success',
  });
  return {
    kind, operationId, transactionHash: txHash.toLowerCase(), idempotencyKeySha256,
    selectedAction: action, transaction, receipt: { ...receiptBody, status: receipt.status, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash },
    gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
    rawResponsePath, rawResponseSha256: sha256Bytes(response.rawBody), persistedEvidence, before, after,
    participantAction: { kind, operationId, rawResponsePath, rawResponseSha256: sha256Bytes(response.rawBody) },
  };
}

async function fenceGeneration(ctx: ProbeContext, session: GenerationSession, caseName: CaseName, suffix: 'planning' | 'actual'): Promise<Record<string, unknown>> {
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: `${caseName}-${suffix}-generation-fence`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/internal/admin/environments/${session.envId}/generations/${session.generationId}/fence`),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' }, body: {},
    operationId: null, variantId: VARIANT_ID,
  });
  const body = record(response.body);
  assert(response.status === 200 && body?.status === 'fenced' && body.signerErased === true,
    `task_v2_reverse_${caseName}_${suffix}_fence_failed_${response.status}`);
  const snapshot = await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, variantId: VARIANT_ID,
    label: `${caseName}-${suffix}-fence-database-proof`,
  });
  assert(snapshot.generation.length === 1 && snapshot.generation[0]?.status === 'fenced',
    `task_v2_reverse_${caseName}_${suffix}_fence_not_persisted`);
  return { status: body.status, signerErased: body.signerErased, generation: snapshot.generation[0] };
}

async function withFencedGeneration<T>(ctx: ProbeContext, session: GenerationSession, caseName: CaseName, suffix: 'planning' | 'actual', work: () => Promise<T>): Promise<{ value: T; fence: Record<string, unknown> }> {
  let value!: T;
  let workFailure: unknown;
  let workFailed = false;
  try { value = await work(); }
  catch (error) { workFailed = true; workFailure = error; }
  let fence: Record<string, unknown>;
  try { fence = await fenceGeneration(ctx, session, caseName, suffix); }
  catch (error) {
    if (workFailed) throw new Error(`task_v2_reverse_${caseName}_${suffix}_work_and_fence_failed`);
    throw error;
  }
  if (workFailed) throw workFailure;
  return { value, fence };
}

async function assertCleanActualGeneration(ctx: ProbeContext, session: GenerationSession, label: CaseName): Promise<void> {
  const facts = await readCaseDatabaseFacts(ctx, session, `${label}-actual-generation-baseline`, VARIANT_ID);
  assert(facts.operations.length === 0 && facts.payments.length === 0 && facts.deliveries.length === 0
    && facts.transactionCosts.length === 0, `task_v2_reverse_${label}_actual_generation_not_clean`);
}

function assertH3NoTradeDuringPaidReference(initial: CaseState, beforeTrade: CaseState, serviceChargeUsdcUnits: string): void {
  assert(initial.payerWethUnits === '0' && initial.wethRouterAllowanceUnits === '0' && initial.usdcRouterAllowanceUnits === '0'
    && beforeTrade.payerWethUnits === initial.payerWethUnits
    && beforeTrade.wethRouterAllowanceUnits === initial.wethRouterAllowanceUnits
    && beforeTrade.usdcRouterAllowanceUnits === initial.usdcRouterAllowanceUnits
    && beforeTrade.payerNativeEthWei === initial.payerNativeEthWei
    && beforeTrade.poolWethUnits === initial.poolWethUnits && beforeTrade.poolUsdcUnits === initial.poolUsdcUnits
    && BigInt(initial.payerUsdcUnits) - BigInt(beforeTrade.payerUsdcUnits) === BigInt(serviceChargeUsdcUnits),
  'task_v2_reverse_h3_paid_reference_changed_unrelated_trade_state');
}

function actionBody(kind: 'wrap' | 'approve' | 'swap', input: { amount: string; minimum?: string; feeTier?: FeeTier; recipient: string }): Record<string, string | number> {
  if (kind === 'wrap') return { amountWei: input.amount, gasLimit: GAS_LIMITS.wrap };
  if (kind === 'approve') return { tokenAssetId: 'WETH', amountUnits: input.amount, gasLimit: GAS_LIMITS.approve };
  return {
    inputAssetId: 'WETH', outputAssetId: 'USDC', feeTier: input.feeTier!, amountInUnits: input.amount,
    amountOutMinimumUnits: input.minimum!, recipient: input.recipient, gasLimit: GAS_LIMITS.swap,
  };
}

async function executeReverseSwap(ctx: ProbeContext, session: GenerationSession, input: {
  caseName: CaseName; amount: string; quote: QuotePlan; beforeTradeState?: CaseState;
}): Promise<{ beforeTrade: CaseState; wrap: CapturedAction; approval: CapturedAction; swap: CapturedAction; final: CaseState }> {
  const beforeTrade = input.beforeTradeState
    ?? await latestCaseState(ctx, session, `${input.caseName}-before-actions`, input.quote.feeTier);
  assert(beforeTrade.payerWethUnits === '0', `task_v2_reverse_${input.caseName}_initial_weth_not_zero`);
  assertZeroAllowances(beforeTrade, input.caseName);
  assert(BigInt(beforeTrade.payerNativeEthWei) >= BigInt(input.amount), `task_v2_reverse_${input.caseName}_native_wrap_balance_insufficient`);
  assert(input.quote.amountInUnits === input.amount && input.quote.feeTier > 0,
    `task_v2_reverse_${input.caseName}_quote_plan_input_mismatch`);
  const wrap = await recordSelectedAction(ctx, session, {
    kind: 'wrap', body: actionBody('wrap', { amount: input.amount, recipient: session.payerAddress }) as Record<string, string>,
    poolFeeTier: input.quote.feeTier, label: `${input.caseName}-wrap`,
  });
  const approval = await recordSelectedAction(ctx, session, {
    kind: 'approve', body: actionBody('approve', { amount: input.amount, recipient: session.payerAddress }) as Record<string, string>,
    poolFeeTier: input.quote.feeTier, label: `${input.caseName}-approve-weth-exact`,
  });
  assert(approval.after.wethRouterAllowanceUnits === input.amount,
    `task_v2_reverse_${input.caseName}_exact_allowance_not_observed`);
  const swap = await recordSelectedAction(ctx, session, {
    kind: 'swap', feeTier: input.quote.feeTier,
    body: actionBody('swap', { amount: input.amount, minimum: input.quote.minimumOutputUnits, feeTier: input.quote.feeTier, recipient: session.payerAddress }) as Record<string, string>,
    poolFeeTier: input.quote.feeTier, label: `${input.caseName}-swap-weth-usdc-fee${input.quote.feeTier}`,
  });
  assert(swap.after.wethRouterAllowanceUnits === '0' && swap.after.usdcRouterAllowanceUnits === '0'
    && swap.after.payerWethUnits === '0', `task_v2_reverse_${input.caseName}_final_weth_or_allowance_not_zero`);
  assert(BigInt(wrap.after.blockNumber) < BigInt(approval.after.blockNumber)
    && BigInt(approval.after.blockNumber) < BigInt(swap.after.blockNumber),
  `task_v2_reverse_${input.caseName}_participant_receipt_order_invalid`);
  return { beforeTrade, wrap, approval, swap, final: swap.after };
}

async function writeCapture(ctx: ProbeContext, caseName: CaseName, session: GenerationSession, capture: Record<string, unknown>, sourceArtifactStart: number): Promise<Record<string, unknown>> {
  const path = `task-v2/captures/${caseName}.json`;
  const sourceArtifacts = ctx.evidence.artifacts.slice(sourceArtifactStart).map(({ path: artifactPath, sha256, boundary }) => ({
    path: artifactPath, sha256, boundary,
  }));
  if (!sourceArtifacts.length) throw new Error(`task_v2_reverse_${caseName}_source_evidence_missing`);
  await ctx.evidence.writeObservation(path, `task-v2-${caseName}-reverse-swap-reference`, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId: null, variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId,
    classification: 'local_fork_observed_candidate_not_task_acceptance_or_release_manifest', sourceArtifacts, capture,
  });
  const artifact = ctx.evidence.artifacts.at(-1);
  assert(artifact?.path === path, `task_v2_reverse_${caseName}_capture_artifact_missing`);
  return {
    ...capture,
    artifact: { path: artifact.path, sha256: artifact.sha256 },
    sourceArtifacts,
  };
}

function participantActionList(actions: CapturedAction[], referenceActions: SplitParticipantAction[] = []) {
  return [
    ...referenceActions.map((action) => ({ ...action })),
    ...actions.map(({ participantAction }) => ({ ...participantAction })),
  ];
}

function costBreakdown(ctx: ProbeContext, input: { amount: string; feeTier: FeeTier; actions: CapturedAction[]; serviceChargeUsdcUnits: string }): Record<string, unknown> {
  const manifest = ctx.runtime.manifest;
  const gasWei = input.actions.map((action) => action.gasCostWei);
  const gasCostWei = gasWei.reduce((sum, amount) => sum + BigInt(amount), 0n);
  const gasCostUsdcUnits = measureAggregateGasUsdcUnits(gasWei, manifest.feePolicy.ethUsdcRateNumerator, manifest.feePolicy.ethUsdcRateDenominator);
  const observedWethInput = requiredString(input.actions.find((action) => action.kind === 'swap')?.observedInputUnits, 'observed_weth_input_units');
  const dexFee = measureDexFee(observedWethInput, input.feeTier, manifest.feePolicy.ethUsdcRateNumerator, manifest.feePolicy.ethUsdcRateDenominator);
  const totalObservedExpenseUsdcUnits = (BigInt(input.serviceChargeUsdcUnits) + BigInt(gasCostUsdcUnits) + BigInt(dexFee.feeUsdcUnits)).toString();
  return {
    classification: 'observed_local_units_no_budget_or_grade_claim',
    serviceChargeUsdcUnits: input.serviceChargeUsdcUnits,
    participantGasCostWei: gasCostWei.toString(), participantGasCostUsdcUnits: gasCostUsdcUnits,
    gasConversion: 'floor_after_summing_participant_receipt_gas_wei_using_manifest_eth_usdc_rational',
    dexFeeWethWei: dexFee.feeWethWei, dexFeeUsdcUnits: dexFee.feeUsdcUnits,
    observedWethInputUnits: observedWethInput,
    dexFeeFormula: 'ceil(observed_weth_input_wei * selected_fee_tier / 1000000), then floor-convert-weth-wei-to-usdc-units',
    ethUsdcRateNumerator: manifest.feePolicy.ethUsdcRateNumerator,
    ethUsdcRateDenominator: manifest.feePolicy.ethUsdcRateDenominator,
    principalWethWei: input.amount, principalExcludedFromExpense: true,
    totalObservedExpenseUsdcUnits,
  };
}

async function assertFinalDatabase(ctx: ProbeContext, session: GenerationSession, caseName: CaseName, expectsPaidReference: boolean): Promise<Record<string, unknown>> {
  const facts = await readCaseDatabaseFacts(ctx, session, `${caseName}-actual-final`, VARIANT_ID);
  const selected = facts.counts.selectedExecutions === '3' && facts.counts.selectedExecutionEvents !== '0'
    && facts.counts.transactionCosts === (expectsPaidReference ? '4' : '3') && facts.counts.participantCosts === '3';
  const payment = expectsPaidReference
    ? facts.counts.offerOperations === '1' && facts.counts.purchaseOperations === '1'
      && facts.counts.payments === '1' && facts.counts.deliveries === '1'
      && facts.payments.length === 1 && facts.deliveries.length === 1
    : facts.counts.offerOperations === '0' && facts.counts.purchaseOperations === '0'
      && facts.counts.payments === '0' && facts.counts.deliveries === '0';
  const operationKinds = facts.operations.map((row) => String(row.operation_kind)).sort();
  const expectedOperationKinds = expectsPaidReference
    ? ['approve', 'offer', 'purchase', 'swap', 'wrap']
    : ['approve', 'swap', 'wrap'];
  assert(facts.operations.length === (expectsPaidReference ? 5 : 3)
    && canonicalJson(operationKinds) === canonicalJson(expectedOperationKinds) && selected && payment,
    `task_v2_reverse_${caseName}_final_database_state_invalid`);
  return { counts: facts.counts, operations: facts.operations, payments: facts.payments, deliveries: facts.deliveries, transactionCosts: facts.transactionCosts };
}

/** Capture M4 with an explicit ranked or training difficulty-profile input. */
export async function captureM4ReverseSwapV2(ctx: ProbeContext, options: { mode: DifficultyMode; profileSource?: ReverseSwapProfileSource }): Promise<Record<string, unknown>> {
  const sourceArtifactStart = ctx.evidence.artifacts.length;
  const source = options.profileSource
    ? validateProvidedDifficultyProfile(ctx, options.profileSource)
    : await loadDifficultyProfile(ctx);
  const amount = resolveM4InputUnits(source.profile, options.mode);
  const caseName: CaseName = options.mode === 'ranked' ? 'm4-ranked' : 'm4-training';
  const planning = await startFreshCaseGeneration(ctx, { caseId: 'm4', scenarioId: ctx.scenarioId, variantId: VARIANT_ID, labelSuffix: 'planning' });
  const planningResult = await withFencedGeneration(ctx, planning, caseName, 'planning',
    () => queryQuote(ctx, planning, amount, 3000, caseName));
  const quote = planningResult.value;
  const session = await startFreshCaseGeneration(ctx, { caseId: 'm4', scenarioId: ctx.scenarioId, variantId: VARIANT_ID, labelSuffix: 'actual' });
  const actualResult = await withFencedGeneration(ctx, session, caseName, 'actual', async () => {
    await assertCleanActualGeneration(ctx, session, caseName);
    const startedAt = Date.now();
    const trade = await executeReverseSwap(ctx, session, { caseName, amount, quote });
    const database = await assertFinalDatabase(ctx, session, caseName, false);
    return { trade, database, elapsedObservedMs: Date.now() - startedAt };
  });
  const { trade, database } = actualResult.value;
  const actions = [trade.wrap, trade.approval, trade.swap];
  const capture = {
    schemaVersion: 'bts-m4-reverse-swap-reference/v2', status: 'observed_candidate', taskId: 'M4', mode: options.mode,
    participantToolProtocol: 'separate_payment_delivery_v2',
    classification: 'local_fork_reference_candidate_not_bts_acceptance',
    difficultyProfile: { profileId: PROFILE_ID, path: PROFILE_PATH, sha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    actionCount: actions.length, participantActionPlan: ['wrap', 'approve:exact-input', 'swap:WETH-to-USDC'], participantActions: participantActionList(actions),
    amountInUnits: amount, inputAssetId: 'WETH', outputAssetId: 'USDC',
    route: { feeTier: quote.feeTier, poolAddress: quote.poolAddress, poolCodeHash: quote.poolCodeHash },
    initial: trade.beforeTrade, quote, actions, final: trade.final,
    measuredCost: costBreakdown(ctx, { amount, feeTier: quote.feeTier, actions, serviceChargeUsdcUnits: '0' }),
    durableDatabase: database, planningGenerationFence: planningResult.fence, actualGenerationFence: actualResult.fence,
    elapsedObservedMs: actualResult.value.elapsedObservedMs,
    releaseReadiness: 'blocked', noAcceptanceClaim: 'No score, task release, production safety, or profitability claim is made.',
  };
  return writeCapture(ctx, caseName, session, capture, sourceArtifactStart);
}

/** Capture H3 from an authenticated split-protocol reference that selects a prequoted pinned route. */
export async function captureH3ReverseSwapV2(ctx: ProbeContext, profileSource?: ReverseSwapProfileSource): Promise<Record<string, unknown>> {
  const sourceArtifactStart = ctx.evidence.artifacts.length;
  const source = profileSource
    ? validateProvidedDifficultyProfile(ctx, profileSource)
    : await loadDifficultyProfile(ctx);
  const task = profileTask(source.profile, 'H3');
  const amount = resolveH3InputUnits(source.profile);
  const resourceId = String(task.referenceResourceId);
  const offerId = String(task.referenceOfferId);
  const caseName: CaseName = 'h3-ranked';
  const planning = await startFreshCaseGeneration(ctx, { caseId: 'h3', scenarioId: ctx.scenarioId, variantId: VARIANT_ID, labelSuffix: 'planning' });
  const planningResult = await withFencedGeneration(ctx, planning, caseName, 'planning', async () => ({
    fee500: await queryQuote(ctx, planning, amount, 500, caseName),
    fee3000: await queryQuote(ctx, planning, amount, 3000, caseName),
  }));
  const quotes = planningResult.value;
  const session = await startFreshCaseGeneration(ctx, { caseId: 'h3', scenarioId: ctx.scenarioId, variantId: VARIANT_ID, labelSuffix: 'actual' });
  const actualResult = await withFencedGeneration(ctx, session, caseName, 'actual', async () => {
    await assertCleanActualGeneration(ctx, session, caseName);
    const initialCaseState = await latestCaseState(ctx, session, `${caseName}-initial-state`);
    assert(initialCaseState.payerWethUnits === '0', 'task_v2_reverse_h3_generation_initial_weth_not_zero');
    assertZeroAllowances(initialCaseState, caseName);
    const startedAt = Date.now();
    const splitRead = await inspectSplitOffer(ctx, session, resourceId, { variantId: VARIANT_ID, label: 'task-v2-h3-route-reference' });
    const splitPayment: SplitPaymentCapture = await payAndRetrieveSplitResource(
      ctx, session, { resourceId, offerId }, splitRead, { variantId: VARIANT_ID, label: 'task-v2-h3-route-reference' },
    );
    const marketDefinition = ctx.runtime.manifest.x402.catalog?.find((entry) => entry.resourceId === resourceId);
    assert(marketDefinition, 'task_v2_reverse_h3_resource_pin_missing');
    const route = projectRouteDelivery({
      envelope: splitPayment.envelope, expectedResourceId: resourceId,
      expectedContentHash: marketDefinition.resourceSha256,
      provenanceId: marketDefinition.provenance.classification,
      routes: [{ value: 'baseline', routeId: 'fee500' }, { value: 'alternative', routeId: 'fee3000' }],
    });
    const feeTier = resolveH3FeeTier(route.projection.routeCode);
    const quote = feeTier === 500 ? quotes.fee500 : quotes.fee3000;
    assert(quote.feeTier === feeTier && quote.amountInUnits === amount,
      'task_v2_reverse_h3_delivered_route_quote_plan_missing');
    const selectedRouteInitialState = await readCaseStateAt(ctx, session,
      `0x${BigInt(initialCaseState.blockNumber).toString(16)}`, initialCaseState.blockHash,
      splitPayment.operationId, `${caseName}-initial-state-selected-pool`, feeTier);
    const serviceChargeUsdcUnits = requiredString(record(splitPayment.paymentReceipt.payment)?.amount, 'h3_service_charge_amount');
    const beforeTradeState = await latestCaseState(ctx, session, `${caseName}-before-actions`, feeTier);
    const paidReceiptBlock = validateH3SettlementBeforeTrade(
      splitPayment.settlementReceipt, splitPayment.transactionHash, beforeTradeState.blockNumber,
    );
    assertH3NoTradeDuringPaidReference(selectedRouteInitialState, beforeTradeState, serviceChargeUsdcUnits);
    const trade = await executeReverseSwap(ctx, session, { caseName, amount, quote, beforeTradeState });
    assertH3NoTradeDuringPaidReference(selectedRouteInitialState, trade.beforeTrade, serviceChargeUsdcUnits);
    assert(validateH3SettlementChronology(
      splitPayment.settlementReceipt, splitPayment.transactionHash,
      trade.beforeTrade.blockNumber, trade.wrap.after.blockNumber,
    ) === paidReceiptBlock, 'task_v2_reverse_h3_paid_receipt_block_changed');
    const database = await assertFinalDatabase(ctx, session, caseName, true);
    return {
      initialCaseState, splitRead, splitPayment, route, feeTier, quote, selectedRouteInitialState, trade, paidReceiptBlock,
      serviceChargeUsdcUnits, database, elapsedObservedMs: Date.now() - startedAt,
    };
  });
  const { initialCaseState, splitRead, splitPayment, route, feeTier, quote, selectedRouteInitialState, trade,
    paidReceiptBlock, serviceChargeUsdcUnits, database } = actualResult.value;
  const actions = [trade.wrap, trade.approval, trade.swap];
  const participantActions = participantActionList(actions, [splitRead.participantAction, ...splitPayment.participantActions]);
  assert(participantActions.length === 6 && participantActions[0]?.kind === 'inspect_offer'
    && participantActions[1]?.kind === 'pay' && participantActions[2]?.kind === 'retrieve'
    && participantActions[3]?.kind === 'wrap' && participantActions[4]?.kind === 'approve'
    && participantActions[5]?.kind === 'swap', 'task_v2_reverse_h3_counted_action_plan_invalid');
  const capture = {
    schemaVersion: 'bts-h3-paid-route-reverse-swap-reference/v2', status: 'observed_candidate', taskId: 'H3', mode: 'ranked',
    participantToolProtocol: 'separate_payment_delivery_v2',
    classification: 'local_fork_reference_candidate_not_bts_acceptance',
    difficultyProfile: { profileId: PROFILE_ID, path: PROFILE_PATH, sha256: source.sha256, manifestSha256: ctx.runtime.manifestSha256 },
    actionCount: participantActions.length,
    participantActionPlan: participantActions.map((action) => action.kind === 'pay' ? 'pay:route-reference'
      : action.kind === 'retrieve' ? 'retrieve:route-reference' : action.kind),
    participantActions,
    paidReference: {
      resourceId, offerId, operationId: splitPayment.operationId, transactionHash: splitPayment.transactionHash,
      paymentReceipt: splitPayment.paymentReceipt, settlementReceipt: splitPayment.settlementReceipt,
      paidReceiptBlockNumber: paidReceiptBlock,
      deliveryProjection: route.projection,
      routeObjective: route.routeObjective, selectedRouteId: route.selectedRouteId,
      routeCode: route.projection.routeCode, deliveryContentBytesSha256: route.contentBytesSha256,
      inspectResponse: { path: splitRead.rawResponsePath, sha256: splitRead.rawResponseSha256 },
      deliveredContent: { path: splitPayment.deliveryContentPath, sha256: splitPayment.deliveryContentSha256 },
      paymentAndRetrieveActions: splitPayment.participantActions,
    },
    amountInUnits: amount, inputAssetId: 'WETH', outputAssetId: 'USDC',
    route: { feeTier, poolAddress: quote.poolAddress, poolCodeHash: quote.poolCodeHash },
    quotePlanning: { fee500: quotes.fee500, fee3000: quotes.fee3000 },
    initialCaseState, initialRoutePoolState: selectedRouteInitialState, initialTradeState: trade.beforeTrade, actions, final: trade.final,
    measuredCost: costBreakdown(ctx, {
      amount, feeTier, actions, serviceChargeUsdcUnits,
    }),
    durableDatabase: database, planningGenerationFence: planningResult.fence, actualGenerationFence: actualResult.fence,
    elapsedObservedMs: actualResult.value.elapsedObservedMs,
    releaseReadiness: 'blocked', noAcceptanceClaim: 'No score, task release, production safety, or profitability claim is made.',
  };
  return writeCapture(ctx, caseName, session, capture, sourceArtifactStart);
}
