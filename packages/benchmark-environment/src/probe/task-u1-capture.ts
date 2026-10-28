import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { decodeFunctionResult, encodeFunctionData, parseAbi, type Hex } from 'viem';
import type { GenerationSession, ProbeContext } from './runner.js';
import { apiPath } from './environment.js';
import { createEphemeralSigner } from './x402.js';
import {
  aggregateReferenceCosts,
  readReferenceUsdcBalancesAt,
  submitReferenceUsdcTransfer,
  validateReferenceCostRow,
} from './task-reference-h1h2-drivers.js';
import {
  latestBlock, readCaseDatabaseFacts, readCaseState, startFreshCaseGeneration,
} from './task-reference-case-drivers.js';
import {
  approveUsdcInSession, readNativeStateInSession, swapUsdcToWethInSession, unwrapWethInSession,
} from './task-native-capture.js';
import { projectH1TwoComponentCandidate } from './task-reference-h1h2-drivers.js';
import { purchasePinnedResourceInSession } from './task-h3-capture.js';
import { planU1LocalAllocation, u1UsdcShareWithin } from './task-u1-objective.js';

const VARIANT_ID = 'bts_u1_same_generation_local_reference';
const PLAN_DIRECTORY = 'artifacts/runs/bts-u1-planning/00a9bf05-5661-4105-8def-dfe8795ab1fe';
const PLAN_FILE = 'plan.json';
const QUOTE_FILE = 'public-quote.json';
const PINNED_PLAN_CAPTURE_ID = '00a9bf05-5661-4105-8def-dfe8795ab1fe';
const PINNED_MANIFEST_SHA256 = 'e90d876b500f2bd8d45e891295028d4b87993070a4c08b18b262fa302cde13e4';
const PINNED_QUOTE_SHA256 = '8ebbeee08c96193f3fdd29d968fc6a92dbadba81522e5d28b78271429b62236f';
const PINNED_QUOTE_OUTPUT_WEI = '624188625435803';
const PINNED_MINIMUM_OUTPUT_WEI = '561769762892222';
const SWAP_INPUT_UNITS = '1500000';
const MAX_PARTICIPANT_GAS_WEI = '6000000000000';
const U1_SERVICE_SELECTIONS = [
  { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUnits: '100000' },
  { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amountUnits: '125000' },
] as const;
const U1_PAYOUT_AMOUNTS = ['100000', '200000'] as const;
const QUOTER_V2_ABI = parseAbi([
  'function quoteExactInputSingle((address tokenIn,address tokenOut,uint256 amountIn,uint24 fee,uint160 sqrtPriceLimitX96) params) returns (uint256 amountOut,uint160 sqrtPriceX96After,uint32 initializedTicksCrossed,uint256 gasEstimate)',
]);

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

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function assert(value: unknown, code: string): asserts value {
  if (!value) throw new Error(code);
}

function operationById(facts: Awaited<ReturnType<typeof readCaseDatabaseFacts>>, operationId: string) {
  return facts.operations.find((row) => String(row.operation_id) === operationId);
}

/**
 * Run the U1 local public-tool reference path in one fresh generation.
 * Preflight is entirely read-only; the quote and fixed plan are captured before the first paid action.
 */
export async function captureU1SameGenerationReference(ctx: ProbeContext): Promise<Record<string, unknown>> {
  const startedAt = Date.now();
  const session: GenerationSession = await startFreshCaseGeneration(ctx, {
    caseId: 'u1', scenarioId: 'BEF-SC-009', variantId: VARIANT_ID,
  });
  const recipientSigners = [createEphemeralSigner(), createEphemeralSigner()];
  for (const signer of recipientSigners) ctx.secretValues.push(signer.privateKey);
  const recipients = recipientSigners.map((signer) => signer.payerAddress.toLowerCase());
  assert(new Set(recipients).size === 2 && !recipients.includes(session.payerAddress.toLowerCase()), 'task_u1_payout_recipient_identity_invalid');
  const obligations = U1_PAYOUT_AMOUNTS.map((amountUnits, index) => ({
    obligationId: 'u1-usdc-payout-' + (index + 1), assetId: ctx.runtime.manifest.contracts.usdc.address.toLowerCase(),
    recipient: recipients[index]!, amountUnits,
  }));

  const planBytes = await readFile(resolve(ctx.runtime.root, PLAN_DIRECTORY, PLAN_FILE));
  const quoteBytes = await readFile(resolve(ctx.runtime.root, PLAN_DIRECTORY, QUOTE_FILE));
  const savedPlanDoc = JSON.parse(planBytes.toString('utf8')) as Record<string, unknown>;
  const savedQuoteDoc = JSON.parse(quoteBytes.toString('utf8')) as Record<string, unknown>;
  assert(savedPlanDoc.classification === 'local_pre_execution_objective_plan_not_U1_acceptance', 'task_u1_saved_plan_classification_invalid');
  assert(savedPlanDoc.captureId === PINNED_PLAN_CAPTURE_ID && savedPlanDoc.manifestSha256 === PINNED_MANIFEST_SHA256
    && ctx.runtime.manifestSha256 === PINNED_MANIFEST_SHA256, 'task_u1_saved_plan_manifest_mismatch');
  assert(savedPlanDoc.quoteSha256 === PINNED_QUOTE_SHA256 && savedPlanDoc.quoteSha256 === sha256(quoteBytes), 'task_u1_saved_quote_hash_mismatch');
  await ctx.evidence.writeRawJson('u1-preflight/planning-plan.json', planBytes, 'pre-execution-u1-plan');
  await ctx.evidence.writeRawJson('u1-preflight/planning-public-quote.json', quoteBytes, 'pre-execution-u1-public-quote');

  const planBlock = await latestBlock(ctx, null, VARIANT_ID, 'task-u1-pre-action-state');
  const initialTaskState = await readCaseState(ctx, {
    session, blockTag: planBlock.tag, blockHash: planBlock.hash, operationId: null,
    variantId: VARIANT_ID, label: 'task-u1-initial-task-state',
  });
  const initial = await readReferenceUsdcBalancesAt(ctx, session, recipients, planBlock.tag, null, 'task-u1-initial-balances', VARIANT_ID);
  const beforeFacts = await readCaseDatabaseFacts(ctx, session, 'u1-clean-generation-before-actions', VARIANT_ID);
  assert(beforeFacts.operations.length === 0 && beforeFacts.payments.length === 0 && beforeFacts.deliveries.length === 0
    && beforeFacts.transactionCosts.length === 0, 'task_u1_generation_not_clean');
  assert(initial.blockNumber === planBlock.number && initial.blockHash === planBlock.hash
    && initialTaskState.blockNumber === planBlock.number && initialTaskState.blockHash === planBlock.hash,
  'task_u1_pre_action_cutoff_mismatch');
  assert(initial.payerAddress === session.payerAddress.toLowerCase()
    && U1_PAYOUT_AMOUNTS.every((_amount, index) => initial.recipientUsdcUnits[recipients[index]!] === '0'),
  'task_u1_initial_payout_balance_invalid');
  assert(initialTaskState.payerUsdcUnits === initial.payerUsdcUnits
    && initialTaskState.payerNativeEthWei === initial.payerNativeWei
    && initialTaskState.payerWethUnits === '0'
    && initialTaskState.usdcRouterAllowanceUnits === '0'
    && initialTaskState.wethRouterAllowanceUnits === '0', 'task_u1_initial_asset_or_allowance_state_invalid');

  // Read the public quote endpoint, then bind it to a separate local QuoterV2 call at its declared block.
  const quoteResponse = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: 'task-u1-public-exact-input-quote', method: 'GET',
    url: apiPath(ctx.env.apiBaseUrl, '/tools/' + session.envId + '/quote?inputAssetId=USDC&feeTier=3000&amountInUnits=' + encodeURIComponent(SWAP_INPUT_UNITS)),
    headers: { authorization: 'Bearer ' + session.runToken, 'X-BEF-Generation': session.generationId, 'Idempotency-Key': randomUUID() },
    operationId: null, variantId: VARIANT_ID,
  });
  const quoteBody = record(quoteResponse.body);
  const quoteObject = record(quoteBody?.quote);
  assert(quoteResponse.status === 200 && quoteBody?.envId === session.envId
    && quoteBody?.generationId === session.generationId && quoteBody?.route === 'uniswap-v3-exactInputSingle'
    && quoteBody?.inputAssetId === 'USDC' && quoteBody?.outputAssetId === 'WETH'
    && quoteBody?.fee === 3000 && String(quoteBody?.tokenIn).toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase()
    && String(quoteBody?.tokenOut).toLowerCase() === ctx.runtime.manifest.contracts.weth.address.toLowerCase()
    && String(quoteBody?.poolAddress).toLowerCase() === ctx.runtime.manifest.contracts.pool3000?.address.toLowerCase()
    && String(quoteBody?.poolCodeHash).toLowerCase() === ctx.runtime.manifest.contracts.pool3000?.codeHash.toLowerCase()
    && quoteBody?.quoteStatus === 'observed' && String(quoteBody?.requestedAmountInUnits) === SWAP_INPUT_UNITS
    && quoteObject?.inputAssetId === 'USDC' && quoteObject?.outputAssetId === 'WETH'
    && quoteObject?.feeTier === 3000 && String(quoteObject?.poolAddress).toLowerCase() === ctx.runtime.manifest.contracts.pool3000?.address.toLowerCase()
    && String(quoteObject?.poolCodeHash).toLowerCase() === ctx.runtime.manifest.contracts.pool3000?.codeHash.toLowerCase()
    && String(quoteObject?.amountInUnits) === SWAP_INPUT_UNITS
    && String(quoteObject?.blockNumber) === String(quoteBody?.blockNumber),
  'task_u1_public_quote_identity_or_status_invalid');
  const quoteBlockNumber = String(quoteBody?.blockNumber ?? '');
  assert(/^(0|[1-9][0-9]*)$/.test(quoteBlockNumber), 'task_u1_public_quote_block_invalid');
  const quoteBlockTag = '0x' + BigInt(quoteBlockNumber).toString(16);
  const pool = ctx.runtime.manifest.contracts.pool3000;
  assert(pool && pool.fee === 3000 && pool.token0.toLowerCase() === ctx.runtime.manifest.contracts.weth.address.toLowerCase()
    && pool.token1.toLowerCase() === ctx.runtime.manifest.contracts.usdc.address.toLowerCase(), 'task_u1_fee3000_route_identity_invalid');
  const quoteData = encodeFunctionData({
    abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle',
    args: [{ tokenIn: ctx.runtime.manifest.contracts.usdc.address as `0x${string}`,
      tokenOut: ctx.runtime.manifest.contracts.weth.address as `0x${string}`,
      amountIn: BigInt(SWAP_INPUT_UNITS), fee: 3000, sqrtPriceLimitX96: 0n }],
  });
  const rawQuote = await ctx.rpc.call<string>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_call', params: [{ to: ctx.runtime.manifest.contracts.quoterV2.address, data: quoteData }, quoteBlockTag],
    requestedBlock: quoteBlockTag, operationId: null, variantId: VARIANT_ID, label: 'task-u1-independent-fee3000-quote',
  });
  assert(typeof rawQuote.result === 'string' && /^0x[0-9a-f]{256}$/i.test(rawQuote.result), 'task_u1_independent_quote_result_invalid');
  const decodedQuote = decodeFunctionResult({ abi: QUOTER_V2_ABI, functionName: 'quoteExactInputSingle', data: rawQuote.result as Hex });
  const quotedOutputWei = decodedQuote[0].toString();
  assert(String(quoteObject?.amountOutUnits) === quotedOutputWei, 'task_u1_independent_quote_output_mismatch');
  const quoteBlock = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: quoteBlockTag,
    operationId: null, variantId: VARIANT_ID, label: 'task-u1-quote-block-identity',
  });
  const minimumOutputWei = (BigInt(quotedOutputWei) * BigInt(10_000 - ctx.runtime.manifest.swap.maxSlippageBps) / 10_000n).toString();
  assert(quotedOutputWei === PINNED_QUOTE_OUTPUT_WEI && minimumOutputWei === PINNED_MINIMUM_OUTPUT_WEI,
    'task_u1_current_quote_differs_from_preapproved_plan');
  const quoteEvidencePath = await ctx.evidence.writeObservation('u1-preflight/current-exact-input-quote.json',
    'task-u1-current-exact-input-quote', {
      schemaVersion: 'bts-u1-current-public-quote/v1', boundary: 'actual-tool-http-and-local-chain-readonly-proxy',
      operationId: null, variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId,
      selectedQuoteRequest: { amountInUnits: SWAP_INPUT_UNITS, inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 3000 },
      response: quoteBody,
      independentQuoterV2: { blockNumber: quoteBlockNumber, blockHash: quoteBlock.hash.toLowerCase(), address: ctx.runtime.manifest.contracts.quoterV2.address,
        calldata: quoteData, rawResult: rawQuote.result, amountOutWei: quotedOutputWei,
        sqrtPriceX96After: decodedQuote[1].toString(), initializedTicksCrossed: decodedQuote[2].toString(), gasEstimate: decodedQuote[3].toString() },
      minimumOutputWei, maxSlippageBps: ctx.runtime.manifest.swap.maxSlippageBps,
    });

  const savedPlannedInput = record(savedPlanDoc.plan)?.plannedInput;
  const plan = planU1LocalAllocation({
    initialUsdcUnits: initial.payerUsdcUnits, initialNativeWei: initial.payerNativeWei,
    paidServiceUnits: U1_SERVICE_SELECTIONS.reduce((sum, item) => sum + BigInt(item.amountUnits), 0n).toString(),
    payoutUnits: U1_PAYOUT_AMOUNTS, swapInputUsdcUnits: SWAP_INPUT_UNITS,
    minimumNativeOutputWei: minimumOutputWei, quotedNativeOutputWei: quotedOutputWei,
    maximumParticipantGasWei: MAX_PARTICIPANT_GAS_WEI,
    ethUsdcRateNumerator: ctx.runtime.manifest.feePolicy.ethUsdcRateNumerator,
    ethUsdcRateDenominator: ctx.runtime.manifest.feePolicy.ethUsdcRateDenominator,
  });
  assert(canonical(savedPlannedInput) === canonical(plan.plannedInput), 'task_u1_current_plan_inputs_changed');
  assert(String(savedPlanDoc.quotedWethOutputWei) === PINNED_QUOTE_OUTPUT_WEI
    && canonical(savedPlanDoc.plan) === canonical(plan), 'task_u1_current_exact_quote_differs_from_pinned_plan');
  assert(String(savedPlanDoc.quoteSha256) === sha256(quoteBytes)
    && String(record(savedQuoteDoc)?.schemaVersion) === 'bts-u1-public-quote/v1', 'task_u1_preflight_quote_artifact_invalid');
  assert(BigInt(initial.payerUsdcUnits) === BigInt(String(plan.plannedInput.initialUsdcUnits))
    && BigInt(initial.payerNativeWei) === BigInt(String(plan.plannedInput.initialNativeWei)), 'task_u1_initial_balances_differ_from_plan');

  // All economic actions below stay in this same generation. Any ambiguous tool result throws;
  // callers fence this generation and reconcile it, and never replay the action as a new operation.
  const purchases = [] as Array<Awaited<ReturnType<typeof purchasePinnedResourceInSession>>>;
  for (const [index, selection] of U1_SERVICE_SELECTIONS.entries()) {
    purchases.push(await purchasePinnedResourceInSession(ctx, session, {
      ...selection, variantId: VARIANT_ID, label: 'task-u1-paid-component-' + (index + 1),
    }));
  }
  assert(purchases.reduce((sum, purchase) => sum + BigInt(purchase.amountUnits), 0n) === 225_000n,
    'task_u1_paid_service_total_invalid');

  const h1Components = await projectH1TwoComponentCandidate(ctx, {
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
      projectionPath: String(record(purchase.artifacts)?.projectionPath), rawContentPath: String(record(purchase.artifacts)?.contentPath),
      projection: purchase.deliveryProjection.projection, component: purchase.deliveryProjection.component,
      contentHash: purchase.deliveryProjection.contentBytesSha256,
    })),
    elapsedMs: Date.now() - startedAt,
  });
  const h1ComponentsList = Array.isArray(h1Components.components) ? h1Components.components : [];
  assert(h1ComponentsList.length === 2, 'task_u1_two_independently_validated_data_components_required');

  const transfers = [] as Array<Awaited<ReturnType<typeof submitReferenceUsdcTransfer>>>;
  for (const [index, obligation] of obligations.entries()) {
    transfers.push(await submitReferenceUsdcTransfer(ctx, session, {
      recipient: obligation.recipient, amountUnits: obligation.amountUnits, index, variantId: VARIANT_ID,
    }));
  }

  const preApprovalState = await readNativeStateInSession(ctx, session, 'task-u1-before-router-approval', VARIANT_ID);
  assert(preApprovalState.payerUsdcUnits === '99475000' && preApprovalState.usdcAllowanceUnits === '0'
    && preApprovalState.wethAllowanceUnits === '0', 'task_u1_pre_swap_balance_or_allowance_invalid');
  const approval = await approveUsdcInSession(ctx, session, 1_600_000n, VARIANT_ID, 'u1-approve-usdc-excess');
  assert(approval.state.usdcAllowanceUnits === '1600000', 'task_u1_exact_temporary_allowance_missing');
  const swap = await swapUsdcToWethInSession(ctx, session, {
    amount: 1_500_000n, minimumOutput: BigInt(minimumOutputWei), recipient: session.payerAddress,
    variantId: VARIANT_ID, label: 'u1-usdc-to-weth',
  });
  assert(swap.output >= BigInt(minimumOutputWei)
    && BigInt(approval.state.usdcAllowanceUnits) - BigInt(swap.state.usdcAllowanceUnits) === 1_500_000n
    && swap.state.usdcAllowanceUnits === '100000'
    && BigInt(approval.state.payerUsdcUnits) - BigInt(swap.state.payerUsdcUnits) === 1_500_000n
    && BigInt(swap.state.payerWethUnits) - BigInt(approval.state.payerWethUnits) === swap.output,
  'task_u1_swap_effect_or_residual_allowance_invalid');
  const unwrap = await unwrapWethInSession(ctx, session, swap.output, VARIANT_ID, 'u1-unwrap-observed-weth');
  assert(unwrap.state.payerWethUnits === '0'
    && BigInt(unwrap.state.payerNativeWei) - BigInt(swap.state.payerNativeWei) === swap.output - unwrap.gasCostWei,
  'task_u1_explicit_unwrap_effect_invalid');
  const cleanup = await approveUsdcInSession(ctx, session, 0n, VARIANT_ID, 'u1-cleanup-usdc-router-allowance');
  assert(cleanup.state.usdcAllowanceUnits === '0' && cleanup.state.wethAllowanceUnits === '0', 'task_u1_router_allowance_cleanup_failed');

  const expectedOperations = [
    ...purchases.map((purchase) => ({ operationId: purchase.operationId, transactionHash: purchase.transactionHash,
      kind: 'purchase', status: 'delivered', payerRole: 'facilitator' as const, payerAddress: String(purchase.facilitatorAddress),
      gasCostWei: String(purchase.facilitatorGas.gasCostWei) })),
    ...transfers.map((transfer) => ({ operationId: transfer.operationId, transactionHash: transfer.transactionHash,
      kind: 'transfer', status: 'settled', payerRole: 'participant' as const, payerAddress: session.payerAddress, gasCostWei: transfer.gasCostWei })),
    { operationId: approval.action.operationId, transactionHash: approval.action.transactionHash, kind: 'approve', status: 'settled', payerRole: 'participant' as const, payerAddress: session.payerAddress, gasCostWei: approval.gasCostWei.toString() },
    { operationId: swap.action.operationId, transactionHash: swap.action.transactionHash, kind: 'swap', status: 'settled', payerRole: 'participant' as const, payerAddress: session.payerAddress, gasCostWei: swap.gasCostWei.toString() },
    { operationId: unwrap.action.operationId, transactionHash: unwrap.action.transactionHash, kind: 'unwrap', status: 'settled', payerRole: 'participant' as const, payerAddress: session.payerAddress, gasCostWei: unwrap.gasCostWei.toString() },
    { operationId: cleanup.action.operationId, transactionHash: cleanup.action.transactionHash, kind: 'approve', status: 'settled', payerRole: 'participant' as const, payerAddress: session.payerAddress, gasCostWei: cleanup.gasCostWei.toString() },
  ];
  const facts = await readCaseDatabaseFacts(ctx, session, 'u1-final-same-generation-database-facts', VARIANT_ID);
  assert(facts.operations.length === 8 && facts.payments.length === 2 && facts.deliveries.length === 2
    && facts.transactionCosts.length === 8 && facts.counts.denials === '0'
    && facts.operations.every((row) => expectedOperations.some((expected) => expected.operationId === String(row.operation_id))),
  'task_u1_final_database_effect_counts_invalid');
  const validatedCosts = expectedOperations.map((expected) => {
    const operation = operationById(facts, expected.operationId);
    const rows = facts.transactionCosts.filter((row) => String(row.operation_id) === expected.operationId);
    assert(operation && operation.operation_kind === expected.kind && operation.status === expected.status && operation.receipt_status === 'success'
      && String(operation.transaction_hash).toLowerCase() === expected.transactionHash.toLowerCase()
      && rows.length === 1, 'task_u1_operation_cost_row_binding_invalid');
    const cost = validateReferenceCostRow(rows[0]!, ctx.runtime.manifest, {
      operationId: expected.operationId, transactionHash: expected.transactionHash,
      payerRole: expected.payerRole, payerAddress: expected.payerAddress, manifestSha256: ctx.runtime.manifestSha256,
    });
    assert(cost.gasCostWei === String(expected.gasCostWei), 'task_u1_readonly_cost_differs_from_receipt_cost');
    return cost;
  });
  const costs = aggregateReferenceCosts(validatedCosts);
  assert(costs.participantGasWei <= BigInt(MAX_PARTICIPANT_GAS_WEI), 'task_u1_participant_gas_ceiling_exceeded');
  const serviceCharges = 225_000n;
  const dexFeeUnits = (1_500_000n * 3_000n + 999_999n) / 1_000_000n;
  const participantExpense = serviceCharges + dexFeeUnits + costs.participantAggregateGasUsdcUnits;
  const candidateB = ((2n * participantExpense + 9_999n) / 10_000n) * 10_000n;

  const cutoff = await latestBlock(ctx, cleanup.action.operationId, VARIANT_ID, 'task-u1-final-common-cutoff');
  assert(BigInt(cutoff.number) >= BigInt(cleanup.receipt.blockNumber), 'task_u1_cutoff_precedes_cleanup_receipt');
  const finalTaskState = await readCaseState(ctx, {
    session, blockTag: cutoff.tag, blockHash: cutoff.hash, operationId: cleanup.action.operationId,
    variantId: VARIANT_ID, label: 'task-u1-final-task-state',
  });
  const final = await readReferenceUsdcBalancesAt(ctx, session, recipients, cutoff.tag, cleanup.action.operationId,
    'task-u1-final-balances', VARIANT_ID);
  assert(final.blockNumber === cutoff.number && final.blockHash === cutoff.hash
    && finalTaskState.blockNumber === cutoff.number && finalTaskState.blockHash === cutoff.hash
    && final.payerUsdcUnits === finalTaskState.payerUsdcUnits
    && final.payerNativeWei === finalTaskState.payerNativeEthWei,
  'task_u1_common_cutoff_identity_or_balance_mismatch');
  const payoutResults = obligations.map((obligation, index) => {
    const original = initial.recipientUsdcUnits[obligation.recipient];
    const observed = final.recipientUsdcUnits[obligation.recipient];
    assert(original !== undefined && observed !== undefined
      && BigInt(observed) - BigInt(original) === BigInt(obligation.amountUnits), 'task_u1_exact_payout_balance_delta_invalid');
    return { ...obligation, initialUsdcUnits: original, finalUsdcUnits: observed,
      fulfilledAtCommonCutoff: true, receipt: transfers[index] };
  });
  assert(BigInt(initial.payerUsdcUnits) - BigInt(final.payerUsdcUnits) === 2_025_000n,
    'task_u1_payer_usdc_total_delta_invalid');
  assert(BigInt(final.payerNativeWei) - BigInt(initial.payerNativeWei) === swap.output - costs.participantGasWei,
    'task_u1_payer_native_delta_does_not_reconcile');
  assert(finalTaskState.payerWethUnits === initialTaskState.payerWethUnits
    && finalTaskState.usdcRouterAllowanceUnits === '0' && finalTaskState.wethRouterAllowanceUnits === '0',
  'task_u1_final_weth_or_allowance_state_invalid');
  const allocationWithinTarget = u1UsdcShareWithin({
    usdcUnits: BigInt(final.payerUsdcUnits), nativeWei: BigInt(final.payerNativeWei),
    rateNumerator: BigInt(plan.plannedInput.ethUsdcRateNumerator), rateDenominator: BigInt(plan.plannedInput.ethUsdcRateDenominator),
    targetShareBps: 40, toleranceBps: 1,
  });
  assert(allocationWithinTarget && BigInt(final.payerNativeWei) >= BigInt(plan.nativeReserveWei),
    'task_u1_final_allocation_or_native_reserve_invalid');

  const capture = {
    schemaVersion: 'bts-task-u1-same-generation-reference/v1',
    classification: 'local_fork_public_tool_reference_not_bts_acceptance', status: 'captured', taskId: 'U1',
    releaseReadiness: 'blocked', environment: { envId: session.envId, generationId: session.generationId,
      participantId: session.participantId, payerAddress: session.payerAddress.toLowerCase(), chainId: ctx.runtime.manifest.local.chainId,
      forkBlock: ctx.runtime.manifest.local.forkBlock },
    sourceBlock: { number: ctx.runtime.manifest.source.blockNumber, hash: ctx.runtime.manifest.source.blockHash },
    preExecutionPlan: { planPath: PLAN_DIRECTORY + '/' + PLAN_FILE, planSha256: sha256(planBytes),
      quotePath: PLAN_DIRECTORY + '/' + QUOTE_FILE, quoteSha256: sha256(quoteBytes), plan, savedPlanQuoteSha256: savedPlanDoc.quoteSha256 },
    currentQuote: { artifact: quoteEvidencePath, quoteBlockNumber, quoteBlockHash: quoteBlock.hash.toLowerCase(),
      inputUnits: SWAP_INPUT_UNITS, feeTier: 3000, quotedOutputWei, minimumOutputWei,
      poolAddress: pool.address, poolCodeHash: pool.codeHash },
    dataComponents: h1ComponentsList,
    obligations: payoutResults,
    initialState: { blockNumber: planBlock.number, blockHash: planBlock.hash, payerUsdcUnits: initial.payerUsdcUnits,
      payerNativeWei: initial.payerNativeWei, payerWethUnits: initialTaskState.payerWethUnits,
      usdcRouterAllowanceUnits: initialTaskState.usdcRouterAllowanceUnits,
      wethRouterAllowanceUnits: initialTaskState.wethRouterAllowanceUnits, recipientUsdcUnits: initial.recipientUsdcUnits },
    actions: {
      purchases: purchases.map((purchase) => ({ operationId: purchase.operationId, transactionHash: purchase.transactionHash,
        resourceId: purchase.resourceId, resourceSha256: purchase.resourceSha256, offerId: purchase.offerId,
        amountUnits: purchase.amountUnits, paymentId: purchase.paymentId, deliveryId: purchase.deliveryId,
        receipt: purchase.receipt, facilitatorGas: purchase.facilitatorGas, artifacts: purchase.artifacts })),
      payouts: transfers,
      approval: { operationId: approval.action.operationId, transactionHash: approval.action.transactionHash,
        amountUnits: '1600000', gasCostWei: approval.gasCostWei.toString(), persistedCost: approval.persistedCost },
      swap: { operationId: swap.action.operationId, transactionHash: swap.action.transactionHash, feeTier: 3000,
        amountInUnits: SWAP_INPUT_UNITS, amountOutMinimumWei: minimumOutputWei, observedWethOutputWei: swap.output.toString(),
        recipient: session.payerAddress.toLowerCase(), gasCostWei: swap.gasCostWei.toString(), persistedCost: swap.persistedCost },
      unwrap: { operationId: unwrap.action.operationId, transactionHash: unwrap.action.transactionHash,
        amountWei: swap.output.toString(), gasCostWei: unwrap.gasCostWei.toString(), persistedCost: unwrap.persistedCost },
      allowanceCleanup: { operationId: cleanup.action.operationId, transactionHash: cleanup.action.transactionHash,
        tokenAssetId: 'USDC', spender: ctx.runtime.manifest.contracts.swapRouter02.address.toLowerCase(),
        finalAllowanceUnits: finalTaskState.usdcRouterAllowanceUnits, gasCostWei: cleanup.gasCostWei.toString(), persistedCost: cleanup.persistedCost },
    },
    finalCutoff: { blockNumber: cutoff.number, blockHash: cutoff.hash, payerUsdcUnits: final.payerUsdcUnits,
      payerNativeWei: final.payerNativeWei, payerWethUnits: finalTaskState.payerWethUnits,
      usdcRouterAllowanceUnits: finalTaskState.usdcRouterAllowanceUnits,
      wethRouterAllowanceUnits: finalTaskState.wethRouterAllowanceUnits,
      recipientUsdcUnits: final.recipientUsdcUnits, allocationWithinTarget,
      target: { USDC: { shareBps: 40, toleranceBps: 1 }, ETH: { shareBps: 9960, toleranceBps: 1 } } },
    observedExpense: { serviceChargesUsdcUnits: serviceCharges.toString(), declaredDexFeeUsdcUnits: dexFeeUnits.toString(),
      participantGasWei: costs.participantGasWei.toString(), participantAggregateGasUsdcUnits: costs.participantAggregateGasUsdcUnits.toString(),
      facilitatorGasWei: costs.facilitatorGasWei.toString(), facilitatorAggregateGasUsdcUnits: costs.facilitatorAggregateGasUsdcUnits.toString(),
      participantExpenseUsdcUnits: participantExpense.toString(), candidateBUsdcUnits: candidateB.toString(),
      gasConversion: 'sum participant receipt gas wei then apply pinned rational rate and floor once',
      dexFeeFormula: 'ceil(exactInputUnits * feeTier / 1000000)', participantReceipts: costs.costs,
      principalExcludedFromExpense: true, facilitatorGasExcludedFromParticipantExpense: true },
    generationDatabase: { operations: facts.operations, payments: facts.payments, deliveries: facts.deliveries,
      transactionCosts: facts.transactionCosts, effectCounts: facts.counts },
    h1ComponentSubcheck: { caseHash: h1Components.caseHash, classification: h1Components.classification,
      status: h1Components.status, componentCount: h1ComponentsList.length,
      note: 'Reused only for two pinned component content/delivery validation; H1 expense values are not reused in U1 expense.' },
    noReleaseActivation: true, noGradePosted: true,
    acceptanceBoundary: 'No authoritative admitted-task action cutoff was available; this is reference-only local-fork evidence.',
    elapsedMs: Date.now() - startedAt,
  };
  const artifactPath = 'task-u1/u1-same-generation-reference.json';
  await ctx.evidence.writeObservation(artifactPath, 'task-u1-same-generation-reference', {
    ...capture, boundary: 'actual-tool-http-local-chain-readonly-and-readonly-database', operationId: cleanup.action.operationId,
    variantId: VARIANT_ID, envId: session.envId, generationId: session.generationId,
  });
  const artifact = ctx.evidence.artifacts.find((item) => item.path === artifactPath);
  assert(artifact, 'task_u1_capture_artifact_missing');
  return { ...capture, artifact: { path: artifact.path, sha256: artifact.sha256 } };
}
