// Project an actual ranked U1 v2 reference capture into TaskCase fields.
// This module is offline: all network/database observations must already be
// retained in the supplied probe artifacts.
import { createHash } from 'node:crypto';
import { canonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';

const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const PARTICIPANT_ACTIONS = [
  'inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve',
  'transfer', 'transfer', 'approve', 'swap', 'unwrap',
];
const EXPECTED_COMPONENTS = [
  { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
  { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amountUsdcUnits: '125000' },
];
const EXPECTED_OBLIGATIONS = [
  { obligationId: 'u1-usdc-payout-1', recipient: '0x3000000000000000000000000000000000000001', amountUsdcUnits: '100000' },
  { obligationId: 'u1-usdc-payout-2', recipient: '0x3000000000000000000000000000000000000002', amountUsdcUnits: '200000' },
];
const EXPECTED_PLANNING = {
  exactInputUsdcUnits: '1500000', feeTier: 3000, slippageBps: 1000,
  maximumParticipantGasWei: '6000000000000',
};

function must(condition, code) {
  if (!condition) throw new Error(code);
}

function record(value, code) {
  must(value !== null && typeof value === 'object' && !Array.isArray(value), code);
  return value;
}

function array(value, code) {
  must(Array.isArray(value), code);
  return value;
}

function uint(value, code) {
  must(typeof value === 'string' && UINT.test(value), code);
  return value;
}

function positiveUint(value, code) {
  const parsed = uint(value, code);
  must(BigInt(parsed) > 0n, code);
  return parsed;
}

function address(value, code) {
  must(typeof value === 'string' && ADDRESS.test(value), code);
  return value.toLowerCase();
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function jsonEqual(left, right) {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function allowanceUnits(snapshot, asset, code) {
  const value = asset === 'USDC'
    ? (snapshot.usdcRouterAllowanceUnits ?? snapshot.usdcAllowanceUnits)
    : (snapshot.wethRouterAllowanceUnits ?? snapshot.wethAllowanceUnits);
  return uint(value, code);
}

function participantSnapshotInput(snapshot) {
  return {
    ...snapshot,
    payerNativeEthWei: snapshot.payerNativeEthWei ?? snapshot.payerNativeWei,
    usdcRouterAllowanceUnits: snapshot.usdcRouterAllowanceUnits ?? snapshot.usdcAllowanceUnits,
    wethRouterAllowanceUnits: snapshot.wethRouterAllowanceUnits ?? snapshot.wethAllowanceUnits,
  };
}

function safePath(value, code) {
  must(typeof value === 'string' && value.length > 0 && value.length <= 512
    && !value.startsWith('/') && !value.includes('\\') && !value.includes(':')
    && value.split('/').every((part) => part && part !== '.' && part !== '..'), code);
  return value;
}

function artifactIndex(probe) {
  const refs = array(probe.artifacts, 'u1_v2_artifact_index_missing');
  const byPath = new Map();
  for (const value of refs) {
    const ref = record(value, 'u1_v2_artifact_ref_invalid');
    const path = safePath(ref.path, 'u1_v2_artifact_path_invalid');
    must(typeof ref.sha256 === 'string' && HASH.test(ref.sha256), 'u1_v2_artifact_hash_invalid');
    must(!byPath.has(path), 'u1_v2_artifact_path_duplicate');
    byPath.set(path, { path, sha256: ref.sha256.toLowerCase(), boundary: ref.boundary });
  }
  return byPath;
}

async function readArtifact(pathValue, expectedHash, byPath, rawArtifact, code) {
  const path = safePath(pathValue, `${code}_path_invalid`);
  const indexed = byPath.get(path);
  must(indexed, `${code}_not_indexed`);
  must(typeof expectedHash === 'string' && HASH.test(expectedHash)
    && indexed.sha256 === expectedHash.toLowerCase(), `${code}_index_hash_mismatch`);
  const result = record(await rawArtifact(path), `${code}_read_failed`);
  must(result.bytes instanceof Uint8Array, `${code}_bytes_missing`);
  const bytes = Buffer.from(result.bytes);
  must(bytes.length > 0 && sha256(bytes) === expectedHash.toLowerCase(), `${code}_hash_mismatch`);
  let value = result.value;
  if (value === undefined) {
    try { value = JSON.parse(bytes.toString('utf8')); }
    catch { throw new Error(`${code}_json_invalid`); }
  }
  return { path, sha256: expectedHash.toLowerCase(), bytes, value };
}

function referenceFor(path, byPath) {
  const safe = safePath(path, 'u1_v2_reference_path_invalid');
  const ref = byPath.get(safe);
  must(ref, 'u1_v2_reference_not_indexed');
  return { path: ref.path, sha256: ref.sha256 };
}

function actionSequence(probe, capture, byPath) {
  const actions = array(capture.participantActions, 'u1_v2_participant_actions_missing');
  const refs = array(probe.captureReferences?.participantActions, 'u1_v2_probe_action_refs_missing');
  must(actions.length === PARTICIPANT_ACTIONS.length && refs.length === PARTICIPANT_ACTIONS.length
    && Number(capture.countedParticipantActions) === PARTICIPANT_ACTIONS.length
    && Number(probe.participantActionCount) === PARTICIPANT_ACTIONS.length,
  'u1_v2_participant_action_count_invalid');
  must(jsonEqual(actions, refs), 'u1_v2_participant_action_reference_mismatch');
  const seenIds = new Set();
  for (let index = 0; index < actions.length; index += 1) {
    const action = record(actions[index], 'u1_v2_participant_action_invalid');
    must(action.kind === PARTICIPANT_ACTIONS[index] && typeof action.operationId === 'string'
      && UUID.test(action.operationId) && typeof action.rawResponseSha256 === 'string'
      && HASH.test(action.rawResponseSha256), 'u1_v2_participant_action_shape_invalid');
    const indexed = byPath.get(safePath(action.rawResponsePath, 'u1_v2_action_path_invalid'));
    must(indexed && indexed.sha256 === action.rawResponseSha256.toLowerCase(), 'u1_v2_action_raw_ref_mismatch');
    const unique = `${action.kind}:${action.operationId}`;
    must(!seenIds.has(unique), 'u1_v2_participant_action_duplicate');
    seenIds.add(unique);
  }
  return actions;
}

async function readAction(actions, index, byPath, rawArtifact) {
  const action = record(actions[index], 'u1_v2_action_missing');
  const raw = await readArtifact(action.rawResponsePath, action.rawResponseSha256, byPath, rawArtifact,
    `u1_v2_action_${index}`);
  const response = record(raw.value, 'u1_v2_action_response_invalid');
  must(response.operationId === action.operationId, 'u1_v2_action_operation_binding_mismatch');
  return { action, response, raw };
}

function manifestResource(manifest, resourceId, code) {
  const catalog = array(manifest.x402?.catalog, `${code}_manifest_catalog_missing`);
  const matches = catalog.filter((item) => item?.resourceId === resourceId);
  must(matches.length === 1, `${code}_resource_not_manifest_pinned`);
  const resource = record(matches[0], `${code}_resource_invalid`);
  must(typeof resource.resourcePath === 'string' && HASH.test(resource.resourceSha256)
    && typeof resource.contentType === 'string' && typeof resource.provenance?.classification === 'string',
  `${code}_resource_manifest_fields_invalid`);
  return resource;
}

function manifestOffer(resource, offerId, amount, code) {
  const offers = array(resource.offers, `${code}_offers_missing`).filter((offer) => offer?.id === offerId);
  must(offers.length === 1 && offers[0].amount === amount, `${code}_offer_manifest_mismatch`);
  return offers[0];
}

function rawCatalogResource(response, resourceId, code) {
  const catalog = array(response.catalog, `${code}_raw_catalog_missing`);
  const matches = catalog.filter((item) => item?.resourceId === resourceId);
  must(matches.length === 1, `${code}_raw_resource_missing`);
  return record(matches[0], `${code}_raw_resource_invalid`);
}

function compareOfferToPublicRead({ rawResource, projectedResource, resource, offerId, amount, manifest, code }) {
  must(rawResource.resourceId === resource.resourceId
    && String(rawResource.resourceSha256).toLowerCase() === resource.resourceSha256.toLowerCase()
    && rawResource.contentType === resource.contentType && rawResource.dataType === resource.dataType
    && rawResource.schema === resource.schema
    && jsonEqual(rawResource.provenance, resource.provenance), `${code}_catalog_resource_mismatch`);
  const rawOffers = array(rawResource.offers, `${code}_raw_offers_missing`).filter((item) => item?.id === offerId);
  must(rawOffers.length === 1, `${code}_raw_offer_missing`);
  const payment = record(rawOffers[0].payment, `${code}_raw_payment_terms_missing`);
  must(payment.amount === amount && payment.scheme === manifest.x402.scheme
    && payment.network === manifest.x402.network
    && address(payment.asset, `${code}_payment_asset_invalid`) === address(manifest.x402.asset, `${code}_manifest_asset_invalid`)
    && payment.transferMethod === manifest.x402.assetTransferMethod,
  `${code}_public_payment_terms_mismatch`);
  const projectedOffers = array(projectedResource.offers, `${code}_projected_offers_missing`)
    .filter((item) => item?.offerId === offerId);
  must(projectedOffers.length === 1, `${code}_projected_offer_missing`);
  const projectedOffer = record(projectedOffers[0], `${code}_projected_offer_invalid`);
  const projectedPayment = record(projectedOffer.paymentRequirements, `${code}_projected_payment_terms_missing`);
  must(projectedOffer.resourceId === resource.resourceId
    && projectedOffer.dataType === resource.dataType
    && projectedOffer.advertisedTotalPriceUsdcUnits === amount
    && projectedOffer.network === payment.network
    && address(projectedOffer.assetId, `${code}_projected_asset_invalid`) === address(payment.asset, `${code}_projected_asset_invalid`)
    && address(projectedOffer.recipient, `${code}_projected_recipient_invalid`) === address(payment.payTo, `${code}_projected_pay_to_invalid`)
    && projectedPayment.scheme === payment.scheme && projectedPayment.resourceId === resource.resourceId
    && projectedPayment.offerId === offerId && projectedPayment.amountUnits === amount
    && projectedPayment.network === payment.network
    && address(projectedPayment.assetId, `${code}_projected_requirements_asset_invalid`) === address(payment.asset, `${code}_payment_asset_invalid`)
    && address(projectedPayment.recipient, `${code}_projected_requirements_recipient_invalid`) === address(payment.payTo, `${code}_payment_pay_to_invalid`),
  `${code}_projected_payment_terms_mismatch`);
  return payment;
}

function eventTopicAddress(value, code) {
  must(typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value), code);
  return `0x${value.slice(-40)}`.toLowerCase();
}

function eventAmount(value, code) {
  must(typeof value === 'string' && /^0x(?:[0-9a-f]{64})$/i.test(value), code);
  return BigInt(value).toString();
}

function wordHex(value, code) {
  const parsed = uint(String(value), code);
  const hex = BigInt(parsed).toString(16);
  must(hex.length <= 64, code);
  return hex.padStart(64, '0');
}

function addressWord(value, code) {
  const parsed = address(value, code).slice(2);
  return parsed.padStart(64, '0');
}

function transferEvent(receipt, token, from, to, amount, code) {
  const logs = array(receipt.logs, `${code}_logs_missing`).filter((log) => {
    const topics = Array.isArray(log?.topics) ? log.topics : [];
    return String(log?.address).toLowerCase() === token.toLowerCase()
      && String(topics[0]).toLowerCase() === TRANSFER_TOPIC
      && topics.length >= 3 && eventTopicAddress(topics[1], `${code}_from_topic_invalid`) === from.toLowerCase()
      && eventTopicAddress(topics[2], `${code}_to_topic_invalid`) === to.toLowerCase()
      && eventAmount(log.data, `${code}_amount_invalid`) === amount;
  });
  must(logs.length === 1 && logs[0].removed !== true, `${code}_transfer_event_mismatch`);
  return logs[0];
}

function participantActionResponse(response, action, kind, payer, code) {
  must(response.outcome === 'success' && response.operationId === action.operationId,
    `${code}_not_successful`);
  const receipt = record(response.receipt, `${code}_receipt_missing`);
  const transaction = record(response.transaction, `${code}_transaction_missing`);
  must(receipt.status === 'success' && transaction.hash?.toLowerCase() === receipt.transactionHash?.toLowerCase()
    && address(receipt.from, `${code}_receipt_from_invalid`) === payer
    && address(transaction.from, `${code}_transaction_from_invalid`) === payer,
  `${code}_receipt_binding_invalid`);
  const selected = record(response.selectedAction, `${code}_selected_action_missing`);
  must(selected.kind === kind, `${code}_selected_action_kind_invalid`);
  return { receipt, transaction, selected };
}

function shareWithin(usdcUnits, nativeWei, numerator, denominator, targetBps, toleranceBps) {
  const usdc = BigInt(usdcUnits), native = BigInt(nativeWei), rateNum = BigInt(numerator), rateDen = BigInt(denominator);
  must(usdc >= 0n && native >= 0n && rateNum > 0n && rateDen > 0n, 'u1_v2_allocation_input_invalid');
  const usdcValue = usdc * rateDen;
  const nativeValue = native * rateNum;
  const total = usdcValue + nativeValue;
  if (total === 0n) return false;
  const low = BigInt(Math.max(0, targetBps - toleranceBps));
  const high = BigInt(Math.min(10000, targetBps + toleranceBps));
  return usdcValue * 10000n >= total * low && usdcValue * 10000n <= total * high;
}

function nativeShareWithin(usdcUnits, nativeWei, numerator, denominator, targetBps, toleranceBps) {
  const usdc = BigInt(usdcUnits), native = BigInt(nativeWei), rateNum = BigInt(numerator), rateDen = BigInt(denominator);
  must(usdc >= 0n && native >= 0n && rateNum > 0n && rateDen > 0n, 'u1_v2_allocation_input_invalid');
  const usdcValue = usdc * rateDen;
  const nativeValue = native * rateNum;
  const total = usdcValue + nativeValue;
  if (total === 0n) return false;
  const low = BigInt(Math.max(0, targetBps - toleranceBps));
  const high = BigInt(Math.min(10000, targetBps + toleranceBps));
  return nativeValue * 10000n >= total * low && nativeValue * 10000n <= total * high;
}

function checkedPlanningProjection({ plan, planArtifact, publicQuote, profileTask, manifest, policy, actualState }) {
  must(planArtifact.schemaVersion === 'bts-u1-difficulty-v2-pre-action-plan/v1'
    && planArtifact.classification === 'fresh_local_pre_execution_plan_not_release_or_execution_proof'
    && planArtifact.taskId === 'U1' && planArtifact.mode === 'ranked'
    && planArtifact.manifestSha256 === actualState.manifestSha256
    && planArtifact.profileSha256 === actualState.profileSha256,
  'u1_v2_pre_action_plan_identity_invalid');
  const generation = record(planArtifact.planningGeneration, 'u1_v2_planning_generation_missing');
  must(generation.envId === actualState.envId && generation.generationId === publicQuote.generationId
    && generation.generationId === actualState.planningGenerationId
    && generation.generationId !== actualState.actualGenerationId,
  'u1_v2_planning_generation_binding_invalid');
  const planningFence = record(actualState.planningFence, 'u1_v2_planning_generation_fence_missing');
  must(planningFence.status === 'fenced' && planningFence.signerErased === true
    && planningFence.databaseGeneration?.status === 'fenced'
    && planningFence.databaseGeneration.generation_id === generation.generationId,
  'u1_v2_planning_generation_fence_missing');

  const quote = record(planArtifact.quote, 'u1_v2_plan_quote_missing');
  const quoteResponse = record(quote.response, 'u1_v2_quote_response_missing');
  must(jsonEqual(quoteResponse, publicQuote)
    && quote.rawResponsePath === actualState.quotePath && quote.rawResponseSha256 === actualState.quoteSha256,
  'u1_v2_plan_quote_artifact_binding_mismatch');
  const quoteBody = record(quoteResponse.quote, 'u1_v2_public_quote_fields_missing');
  const pool = record(manifest.contracts?.pool3000, 'u1_v2_fee3000_pool_missing');
  const tokenIn = address(manifest.contracts?.usdc?.address, 'u1_v2_usdc_contract_missing');
  const tokenOut = address(manifest.contracts?.weth?.address, 'u1_v2_weth_contract_missing');
  const expectedInput = positiveUint(profileTask.planning?.exactInputUsdcUnits, 'u1_v2_profile_swap_input_invalid');
  const feeTier = Number(profileTask.planning?.feeTier);
  const slippageBps = Number(profileTask.planning?.slippageBps);
  must(feeTier === 3000 && Number.isInteger(slippageBps) && slippageBps >= 0 && slippageBps < 10000
    && quoteResponse.boundary === 'local-chain-readonly-proxy' && quoteResponse.quoteStatus === 'observed'
    && quoteResponse.envId === generation.envId && quoteResponse.generationId === generation.generationId
    && quoteResponse.route === 'uniswap-v3-exactInputSingle' && quoteResponse.inputAssetId === 'USDC'
    && quoteResponse.outputAssetId === 'WETH' && address(quoteResponse.tokenIn, 'u1_v2_quote_token_in_invalid') === tokenIn
    && address(quoteResponse.tokenOut, 'u1_v2_quote_token_out_invalid') === tokenOut
    && address(quoteResponse.poolAddress, 'u1_v2_quote_pool_address_invalid') === address(pool.address, 'u1_v2_manifest_pool_address_invalid')
    && String(quoteResponse.poolCodeHash).replace(/^0x/i, '').toLowerCase()
      === String(pool.codeHash).replace(/^0x/i, '').toLowerCase()
    && Number(quoteResponse.fee) === feeTier && quoteResponse.requestedAmountInUnits === expectedInput
    && quoteBody.feeTier === feeTier && quoteBody.inputAssetId === 'USDC' && quoteBody.outputAssetId === 'WETH'
    && quoteBody.amountInUnits === expectedInput && String(quoteBody.feeTier) === String(quoteResponse.fee)
    && address(quoteBody.poolAddress, 'u1_v2_quote_body_pool_invalid') === address(pool.address, 'u1_v2_manifest_pool_address_invalid')
    && String(quoteBody.poolCodeHash).replace(/^0x/i, '').toLowerCase()
      === String(pool.codeHash).replace(/^0x/i, '').toLowerCase()
    && String(quoteBody.blockNumber) === String(quoteResponse.blockNumber)
    && String(quoteResponse.blockNumber) === String(quote.quoteBlockNumber)
    && String(quoteResponse.blockNumber) === String(planArtifact.initialState?.blockNumber)
    && typeof quote.quoteBlockHash === 'string' && /^0x[0-9a-f]{64}$/i.test(quote.quoteBlockHash)
    && quote.quoteBlockHash.toLowerCase() === String(planArtifact.initialState?.blockHash).toLowerCase()
    && address(quote.quoterAddress, 'u1_v2_quoter_address_invalid')
      === address(manifest.contracts?.quoterV2?.address, 'u1_v2_manifest_quoter_missing'),
  'u1_v2_public_quote_contract_binding_invalid');

  const quotedOutput = positiveUint(quoteBody.amountOutUnits, 'u1_v2_quote_output_invalid');
  const independentResult = quote.independentResult;
  must(typeof independentResult === 'string' && /^0x[0-9a-f]{256}$/i.test(independentResult),
    'u1_v2_independent_quoter_result_invalid');
  const independentAmount = BigInt(`0x${independentResult.slice(2, 66)}`).toString();
  const decoded = record(quote.decoded, 'u1_v2_independent_quote_decode_missing');
  must(independentAmount === quotedOutput && decoded.amountOutWei === independentAmount
    && decoded.sqrtPriceX96After === quoteBody.sqrtPriceX96After
    && decoded.initializedTicksCrossed === quoteBody.initializedTicksCrossed
    && decoded.gasEstimate === quoteBody.gasEstimate
    && quote.quotedOutputWei === independentAmount && String(quote.minimumOutputWei) === String(plan.plannedInput?.minimumNativeOutputWei),
  'u1_v2_independent_quote_output_mismatch');
  const expectedCallData = `0xc6a5026a${addressWord(tokenIn, 'u1_v2_quote_calldata_token_in_invalid')}`
    + `${addressWord(tokenOut, 'u1_v2_quote_calldata_token_out_invalid')}`
    + `${wordHex(expectedInput, 'u1_v2_quote_calldata_amount_invalid')}`
    + `${wordHex(String(feeTier), 'u1_v2_quote_calldata_fee_invalid')}${'0'.repeat(64)}`;
  must(String(quote.quoteData).toLowerCase() === expectedCallData, 'u1_v2_independent_quote_calldata_invalid');
  const minimumOutput = (BigInt(quotedOutput) * BigInt(10000 - slippageBps) / 10000n).toString();
  must(minimumOutput === String(quote.minimumOutputWei), 'u1_v2_quote_slippage_floor_mismatch');

  const input = record(plan.plannedInput, 'u1_v2_planned_input_missing');
  const initial = record(planArtifact.initialState, 'u1_v2_planning_initial_state_missing');
  const expectedService = profileTask.components.reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n).toString();
  const expectedPayouts = profileTask.obligations.map((item) => item.amountUsdcUnits);
  const rateNumerator = positiveUint(manifest.feePolicy?.ethUsdcRateNumerator, 'u1_v2_rate_numerator_missing');
  const rateDenominator = positiveUint(manifest.feePolicy?.ethUsdcRateDenominator, 'u1_v2_rate_denominator_missing');
  must(input.initialUsdcUnits === uint(initial.payerUsdcUnits, 'u1_v2_plan_initial_usdc_invalid')
    && input.initialNativeWei === uint(initial.payerNativeWei, 'u1_v2_plan_initial_native_invalid')
    && input.initialUsdcUnits === actualState.initialUsdcUnits
    && input.initialNativeWei === actualState.initialNativeWei
    && input.paidServiceUnits === expectedService
    && jsonEqual(input.payoutUnits, expectedPayouts)
    && input.swapInputUsdcUnits === expectedInput
    && input.minimumNativeOutputWei === minimumOutput
    && input.quotedNativeOutputWei === quotedOutput
    && input.maximumParticipantGasWei === profileTask.planning.maximumParticipantGasWei
    && input.ethUsdcRateNumerator === rateNumerator && input.ethUsdcRateDenominator === rateDenominator,
  'u1_v2_plan_input_not_bound_to_profile_and_quote');

  const initialSolved = shareWithin(input.initialUsdcUnits, input.initialNativeWei,
    rateNumerator, rateDenominator, 40, 1);
  const finalUsdc = (BigInt(input.initialUsdcUnits) - BigInt(input.paidServiceUnits)
    - expectedPayouts.reduce((sum, value) => sum + BigInt(value), 0n) - BigInt(input.swapInputUsdcUnits)).toString();
  const minimumNative = (BigInt(input.initialNativeWei) + BigInt(input.minimumNativeOutputWei)
    - BigInt(input.maximumParticipantGasWei)).toString();
  const maximumNative = (BigInt(input.initialNativeWei) + BigInt(input.quotedNativeOutputWei)).toString();
  const minimumWithin = shareWithin(finalUsdc, minimumNative, rateNumerator, rateDenominator, 40, 1);
  const maximumWithin = shareWithin(finalUsdc, maximumNative, rateNumerator, rateDenominator, 40, 1);
  const reserveWei = (BigInt(input.initialNativeWei) - BigInt(input.maximumParticipantGasWei)).toString();
  const allocationAssets = array(plan.allocationAssets, 'u1_v2_plan_allocation_assets_missing');
  const expectedRate = { numerator: rateNumerator, denominator: rateDenominator };
  must(!initialSolved && plan.initiallySolved === false
    && minimumWithin && maximumWithin
    && jsonEqual(plan.projectedBounds, { finalUsdcUnits: finalUsdc, minimumNativeWei: minimumNative, maximumNativeWei: maximumNative })
    && plan.nativeReserveWei === reserveWei && reserveWei === policy.nativeReserveWei?.U1
    && plan.requiresExactInputPublicQuote === true
    && jsonEqual(plan.targetSharesBps, { USDC: 40, ETH: 9960, WETH: 0 })
    && jsonEqual(plan.assetToleranceBps, { USDC: 1, ETH: 1, WETH: 0 })
    && allocationAssets.length === 3
    && jsonEqual(allocationAssets.map((asset) => asset.assetId), ['USDC', 'ETH', 'WETH'])
    && jsonEqual(allocationAssets[0], { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 40, toleranceBps: 1 })
    && jsonEqual(allocationAssets[1], { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: expectedRate, targetShareBps: 9960, toleranceBps: 1 })
    && jsonEqual(allocationAssets[2], { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: expectedRate, targetShareBps: 0, toleranceBps: 0 }),
  'u1_v2_pre_action_allocation_plan_invalid');
  return {
    independentlyRecomputedInitiallySolved: initialSolved,
    independentlyRecomputedProjectedBounds: {
      finalUsdcUnits: finalUsdc, minimumNativeWei: minimumNative, maximumNativeWei: maximumNative,
      minimumOutputWithinTarget: minimumWithin, maximumOutputWithinTarget: maximumWithin,
    },
    nativeReserveWei: reserveWei,
    exactInputUsdcUnits: expectedInput,
    feeTier,
    slippageBps,
    planningGenerationId: generation.generationId,
    quoteBlockNumber: String(quoteResponse.blockNumber),
  };
}

function checkProfileTask(task) {
  must(task.rankedOnly === true && Number(task.countedParticipantActions) === 10
    && jsonEqual(task.participantActionPlan, [
      'inspect_catalog', 'pay:component-1', 'retrieve:component-1', 'pay:component-2', 'retrieve:component-2',
      'transfer:obligation-1', 'transfer:obligation-2', 'approve:exact-input', 'swap:USDC-to-WETH', 'unwrap',
    ])
    && Number(task.requiredDistinctPaidComponents) === 2 && Number(task.requiredDistinctObligations) === 2
    && jsonEqual(task.components, EXPECTED_COMPONENTS) && jsonEqual(task.obligations, EXPECTED_OBLIGATIONS)
    && jsonEqual(task.allocationAssets, ['USDC', 'ETH', 'WETH'])
    && jsonEqual(task.targetSharesBps, { USDC: 40, ETH: 9960, WETH: 0 })
    && jsonEqual(task.assetToleranceBps, { USDC: 1, ETH: 1, WETH: 0 })
    && Number(task.toleranceBps) === 1
    && task.cleanupPolicy === 'exact_approval_can_leave_zero_scope_without_creating_an_extra_allowance'
    && task.swapPrincipalPolicy === 'pin_from_fresh_pre_action_plan_and_public_quote'
    && jsonEqual(task.planning, {
      ...EXPECTED_PLANNING,
      validation: 'fresh_public_quote_and_independent_quoter_before_actual_generation; reject_if_fixed_target_not_reached_at_both_gas_output_bounds',
    }), 'u1_v2_profile_task_contract_invalid');
}

function checkPlanningSnapshotMatchesActual(planning, actual, profileTask) {
  must(planning.payerUsdcUnits === actual.payerUsdcUnits
    && planning.payerNativeWei === actual.payerNativeWei
    && planning.payerWethUnits === actual.payerWethUnits
    && planning.usdcAllowanceUnits === actual.usdcAllowanceUnits
    && planning.wethAllowanceUnits === actual.wethAllowanceUnits
    && jsonEqual(planning.recipientUsdcUnits, actual.recipientUsdcUnits)
    && planning.payerWethUnits === '0' && planning.usdcAllowanceUnits === '0' && planning.wethAllowanceUnits === '0'
    && planning.payerUsdcUnits === '100000000'
    && planning.payerNativeWei === '10000000000000000000'
    && jsonEqual(Object.keys(planning.recipientUsdcUnits).sort(), profileTask.obligations.map((item) => item.recipient).sort()),
  'u1_v2_planning_and_actual_initial_state_mismatch');
}

function checkOperation(durable, operationId, expectedKind, expectedStatus, receiptStatus, txHash, code) {
  const rows = array(durable.operations, `${code}_operations_missing`)
    .filter((row) => row?.operation_id === operationId);
  must(rows.length === 1, `${code}_operation_not_durable`);
  const row = record(rows[0], `${code}_operation_invalid`);
  must(row.operation_kind === expectedKind && row.status === expectedStatus
    && row.receipt_status === receiptStatus
    && (txHash === null ? row.transaction_hash === null : String(row.transaction_hash).toLowerCase() === txHash.toLowerCase()),
  `${code}_operation_state_mismatch`);
  return row;
}

function checkCostRow(costRows, receiptRows, operationId, payer, transactionHash, receipt, manifestSha, code) {
  const rows = costRows.filter((row) => row?.operation_id === operationId);
  must(rows.length === 1, `${code}_durable_cost_missing`);
  const row = record(rows[0], `${code}_durable_cost_invalid`);
  must(row.payer_role === 'participant' && address(row.payer_address, `${code}_cost_payer_invalid`) === payer
    && row.receipt_status === 'success' && String(row.transaction_hash).toLowerCase() === transactionHash.toLowerCase()
    && String(row.gas_used) === String(receipt.gasUsed)
    && String(row.effective_gas_price_wei) === String(receipt.effectiveGasPrice)
    && uint(row.gas_cost_wei, `${code}_durable_gas_invalid`) === uint(receipt.gasCostWei, `${code}_receipt_gas_invalid`)
    && String(row.manifest_sha256).toLowerCase() === manifestSha.toLowerCase(), `${code}_durable_cost_binding_mismatch`);
  const captured = receiptRows.filter((item) => item?.operationId === operationId);
  must(captured.length === 1 && captured[0].payerRole === 'participant'
    && String(captured[0].transactionHash).toLowerCase() === transactionHash.toLowerCase()
    && captured[0].receiptStatus === 'success' && captured[0].gasCostWei === row.gas_cost_wei,
  `${code}_capture_cost_binding_mismatch`);
  return row;
}

function checkCaptureFence(probe, capture, planningFence) {
  const actual = record(probe.generationFence, 'u1_v2_actual_generation_fence_missing');
  const observer = record(actual.independentObserver, 'u1_v2_generation_observer_missing');
  must(actual.status === 'fenced' && actual.signerErased === true
    && actual.envId === probe.environment?.envId && actual.generationId === probe.environment?.generationId
    && observer.status === 'fenced' && observer.economicOutcome === 'settled_or_absent'
    && Number(observer.unresolvedOperationCount) === 0
    && array(observer.unresolvedOperations ?? [], 'u1_v2_unresolved_operations_invalid').length === 0
    && planningFence?.status === 'fenced' && planningFence.signerErased === true,
  'u1_v2_generation_fence_not_confirmed');
}

/**
 * Project the retained U1 capture. Throws on any incomplete, contradictory, or
 * non-profile evidence; it does not post grades or activate a release.
 */
export async function projectU1V2Candidate({ probe, manifest, identity, policy, rawArtifact, helpers }) {
  record(probe, 'u1_v2_probe_missing');
  record(manifest, 'u1_v2_manifest_missing');
  record(identity, 'u1_v2_identity_missing');
  record(policy, 'u1_v2_policy_missing');
  record(helpers, 'u1_v2_helpers_missing');
  must(typeof rawArtifact === 'function' && typeof helpers.state === 'function'
    && typeof helpers.participantState === 'function' && typeof helpers.assetId === 'function'
    && typeof helpers.budget === 'function' && typeof helpers.route === 'function'
    && typeof helpers.component === 'function' && typeof helpers.readPinnedResource === 'function'
    && typeof helpers.projectDeliveryEnvelope === 'function', 'u1_v2_projection_helpers_missing');
  const capture = record(probe.capture, 'u1_v2_capture_missing');
  must(probe.status === 'captured' && probe.taskId === 'U1' && probe.mode === 'ranked'
    && capture.taskId === 'U1' && capture.mode === 'ranked' && capture.status === 'captured_candidate'
    && capture.releaseReadiness === 'blocked' && capture.noReleaseActivation === true && capture.noGradePosted === true
    && probe.noTaskGrade === true && probe.noReleaseActivation === true && probe.noAcceptanceClaim === true
    && probe.releaseReadiness === 'blocked', 'u1_v2_probe_identity_or_claim_boundary_invalid');
  const byPath = artifactIndex(probe);
  const actions = actionSequence(probe, capture, byPath);
  const caseRef = record(probe.captureReferences?.caseArtifact, 'u1_v2_case_artifact_ref_missing');
  const caseArtifact = await readArtifact(caseRef.path, caseRef.sha256, byPath, rawArtifact, 'u1_v2_case_artifact');
  const caseArtifactValue = record(caseArtifact.value, 'u1_v2_case_artifact_invalid');
  must(Object.keys(capture).every((key) => jsonEqual(caseArtifactValue[key], capture[key]))
    && caseArtifactValue.schemaVersion === capture.schemaVersion
    && caseArtifactValue.operationId === capture.actions?.unwrap?.operationId
    && caseArtifactValue.variantId === 'bts_u1_ranked_difficulty_v2_reference'
    && caseArtifactValue.envId === probe.environment?.envId
    && caseArtifactValue.generationId === probe.environment?.generationId,
  'u1_v2_case_artifact_capture_mismatch');

  const profileRef = record(capture.sourceProfile, 'u1_v2_source_profile_ref_missing');
  must(profileRef.mode === 'ranked' && profileRef.path === probe.difficultyProfile?.sourcePath
    && profileRef.sha256 === probe.difficultyProfile?.sourceSha256
    && profileRef.sha256 === probe.difficultyProfile?.evidenceSha256
    && probe.difficultyProfile?.evidencePath === 'task-u1-v2/source-profile.json',
  'u1_v2_source_profile_identity_mismatch');
  const profilePath = 'task-u1-v2/source-profile.json';
  const profileArtifact = await readArtifact(profilePath, profileRef.sha256, byPath, rawArtifact, 'u1_v2_source_profile');
  const sourceProfile = record(profileArtifact.value, 'u1_v2_source_profile_invalid');
  const profileTask = record(sourceProfile.tasks?.U1, 'u1_v2_profile_task_missing');
  checkProfileTask(profileTask);
  must(sourceProfile.schemaVersion === 'bts-task-case-input-profile/v2'
    && sourceProfile.profileId === 'bts-task-difficulty-v2'
    && sourceProfile.runtimeManifest?.sha256 === capture.manifestSha256
    && sourceProfile.status === 'source_profile_candidate_unactivated', 'u1_v2_profile_identity_invalid');
  const manifestRef = record(probe.manifest, 'u1_v2_manifest_ref_missing');
  must(String(manifestRef.sha256).toLowerCase() === String(capture.manifestSha256).toLowerCase()
    && String(sourceProfile.runtimeManifest.sha256).toLowerCase() === String(capture.manifestSha256).toLowerCase(),
  'u1_v2_manifest_hash_mismatch');
  must(typeof manifest.x402?.scheme === 'string' && typeof manifest.x402?.network === 'string'
    && typeof manifest.x402?.asset === 'string' && typeof manifest.x402?.assetTransferMethod === 'string'
    && Number(manifest.contracts?.pool3000?.fee) === EXPECTED_PLANNING.feeTier
    && address(manifest.contracts?.pool3000?.token0, 'u1_v2_pool_token0_invalid') === address(manifest.contracts?.weth?.address, 'u1_v2_weth_contract_missing')
    && address(manifest.contracts?.pool3000?.token1, 'u1_v2_pool_token1_invalid') === address(manifest.contracts?.usdc?.address, 'u1_v2_usdc_contract_missing'),
  'u1_v2_manifest_route_invalid');
  must(policy.expenseBudget?.excludePrincipal === true && policy.expenseBudget?.excludeSponsoredFacilitatorGas === true
    && policy.expenseBudget?.dexFeeConversion === 'ceil_exact_input_units_times_fee_tier_over_1000000'
    && policy.expenseBudget?.participantGasConversion === 'floor_after_summing_receipt_gas_wei_at_pinned_rate'
    && policy.expenseBudget?.pinOnceAfterReferenceBeforeReleaseActivation === true,
  'u1_v2_expense_policy_invalid');

  const payer = address(probe.environment?.payerAddress, 'u1_v2_payer_address_invalid');
  const actualGenerationId = probe.environment?.generationId;
  const actualEnvId = probe.environment?.envId;
  const initialRaw = record(capture.initialState, 'u1_v2_initial_state_missing');
  const finalRaw = record(capture.finalCutoff, 'u1_v2_final_cutoff_missing');
  must(address(initialRaw.payerAddress, 'u1_v2_initial_payer_invalid') === payer
    && initialRaw.payerWethUnits === '0' && allowanceUnits(initialRaw, 'USDC', 'u1_v2_initial_usdc_allowance_invalid') === '0'
    && allowanceUnits(initialRaw, 'WETH', 'u1_v2_initial_weth_allowance_invalid') === '0'
    && uint(finalRaw.payerWethUnits, 'u1_v2_final_weth_invalid') === '0'
    && uint(finalRaw.usdcRouterAllowanceUnits, 'u1_v2_final_usdc_allowance_invalid') === '0'
    && uint(finalRaw.wethRouterAllowanceUnits, 'u1_v2_final_weth_allowance_invalid') === '0',
  'u1_v2_initial_or_final_allowance_scope_invalid');
  const initialRecipients = record(initialRaw.recipientUsdcUnits, 'u1_v2_initial_recipient_map_missing');
  const finalRecipients = record(finalRaw.recipientUsdcUnits, 'u1_v2_final_recipient_map_missing');
  const initialUsdcUnits = uint(initialRaw.payerUsdcUnits, 'u1_v2_initial_usdc_invalid');
  const initialNativeWei = uint(initialRaw.payerNativeWei, 'u1_v2_initial_native_invalid');

  const planning = record(capture.planning, 'u1_v2_planning_record_missing');
  const planningInitial = record(planning.initialState, 'u1_v2_planning_initial_state_missing');
  checkPlanningSnapshotMatchesActual(planningInitial, initialRaw, profileTask);
  const quote = record(planning.quote, 'u1_v2_planning_quote_missing');
  const quoteArtifact = await readArtifact(quote.rawResponsePath, quote.rawResponseSha256, byPath, rawArtifact, 'u1_v2_public_quote');
  const planArtifactRef = { path: planning.planPath, sha256: planning.planSha256 };
  const planFile = await readArtifact(planArtifactRef.path, planArtifactRef.sha256, byPath, rawArtifact, 'u1_v2_pre_action_plan');
  const preActionFile = record(planFile.value, 'u1_v2_pre_action_plan_invalid');
  const plan = record(preActionFile.plan, 'u1_v2_pre_action_allocation_missing');
  const planValidation = checkedPlanningProjection({
    plan, planArtifact: preActionFile, publicQuote: quoteArtifact.value, profileTask, manifest, policy,
    actualState: { envId: actualEnvId, actualGenerationId, manifestSha256: capture.manifestSha256,
      profileSha256: profileRef.sha256, planningGenerationId: planning.generationId,
      quotePath: quote.rawResponsePath, quoteSha256: quote.rawResponseSha256,
      planningFence: planning.fence,
      initialUsdcUnits, initialNativeWei },
  });
  must(preActionFile.quote.rawResponsePath === quote.rawResponsePath
    && preActionFile.quote.rawResponseSha256 === quote.rawResponseSha256
    && planning.generationId === planValidation.planningGenerationId
    && planning.generationId !== actualGenerationId,
  'u1_v2_pre_action_plan_reference_mismatch');
  checkCaptureFence(probe, capture, planning.fence);

  const catalogAction = await readAction(actions, 0, byPath, rawArtifact);
  const catalog = record(capture.catalog, 'u1_v2_catalog_projection_missing');
  const catalogProjection = record(catalog.projection, 'u1_v2_catalog_projection_invalid');
  must(catalogAction.action.kind === 'inspect_catalog' && catalog.operationId === catalogAction.action.operationId
    && catalog.rawResponsePath === catalogAction.action.rawResponsePath
    && catalog.rawResponseSha256 === catalogAction.action.rawResponseSha256
    && catalogAction.response.readHandle?.kind === 'catalog'
    && catalogAction.response.readHandle?.operationId === catalogAction.action.operationId
    && catalogAction.response.freeInspection === true && catalogAction.response.deliveryState === 'not_delivered',
  'u1_v2_catalog_action_binding_invalid');
  const expectedPayerId = helpers.assetId(identity, manifest.contracts.usdc.address);
  const ethAssetId = helpers.assetId(identity, 'ETH');
  const wethAssetId = helpers.assetId(identity, manifest.contracts.weth.address);
  must(expectedPayerId === 'USDC' && ethAssetId === 'ETH' && wethAssetId === 'WETH',
    'u1_v2_asset_identity_invalid');
  const router = address(manifest.contracts?.swapRouter02?.address, 'u1_v2_router_missing');

  const componentRows = array(capture.components, 'u1_v2_components_missing');
  must(componentRows.length === EXPECTED_COMPONENTS.length, 'u1_v2_component_count_invalid');
  const projectedComponents = [];
  const componentRefs = [];
  const paymentRows = array(capture.actions?.payments, 'u1_v2_payment_actions_missing');
  must(paymentRows.length === componentRows.length, 'u1_v2_payment_action_count_invalid');
  const durable = record(capture.durableState, 'u1_v2_durable_state_missing');
  const serviceAmounts = [];
  for (let index = 0; index < componentRows.length; index += 1) {
    const capturedComponent = record(componentRows[index], 'u1_v2_component_invalid');
    const expected = profileTask.components[index];
    const code = `u1_v2_component_${index + 1}`;
    must(capturedComponent.componentId === expected.resourceId
      && capturedComponent.resourceId === expected.resourceId && capturedComponent.offerId === expected.offerId
      && capturedComponent.amountUsdcUnits === expected.amountUsdcUnits,
    `${code}_profile_binding_mismatch`);
    const resource = manifestResource(manifest, expected.resourceId, code);
    const offer = manifestOffer(resource, expected.offerId, expected.amountUsdcUnits, code);
    const rawResource = rawCatalogResource(catalogAction.response, expected.resourceId, code);
    const projectedResourceRows = array(catalogProjection.resources, `${code}_catalog_projection_resources_missing`)
      .filter((item) => item?.resourceId === expected.resourceId);
    must(projectedResourceRows.length === 1, `${code}_catalog_projection_resource_missing`);
    const paymentTerms = compareOfferToPublicRead({ rawResource, projectedResource: projectedResourceRows[0],
      resource, offerId: expected.offerId, amount: expected.amountUsdcUnits, manifest, code });
    must(String(catalogProjection.resourceHashes?.[expected.resourceId]).toLowerCase() === resource.resourceSha256.toLowerCase(),
      `${code}_catalog_resource_hash_mismatch`);

    const payAction = await readAction(actions, index * 2 + 1, byPath, rawArtifact);
    const retrieveAction = await readAction(actions, index * 2 + 2, byPath, rawArtifact);
    must(payAction.action.kind === 'pay' && retrieveAction.action.kind === 'retrieve'
      && payAction.action.operationId === capturedComponent.deliveryOperationId
      && retrieveAction.action.operationId === capturedComponent.deliveryOperationId
      && payAction.action.operationId === paymentRows[index].operationId
      && payAction.action.operationId === retrieveAction.response.operationId,
    `${code}_action_operation_binding_mismatch`);
    const payBody = payAction.response;
    const payResult = record(payBody.payment, `${code}_payment_receipt_missing`);
    const savedPayment = record(capturedComponent.paymentReceipt, `${code}_captured_payment_missing`);
    const transactionHash = String(payResult.transactionHash ?? '').toLowerCase();
    must(payBody.status === 'payment_confirmed' && payBody.deliveryHandle === payAction.action.operationId
      && payBody.operationId === payAction.action.operationId && payResult.receiptStatus === 'success'
      && /^0x[0-9a-f]{64}$/i.test(transactionHash)
      && payResult.amount === expected.amountUsdcUnits
      && address(payResult.asset, `${code}_payment_asset_invalid`) === address(manifest.x402.asset, `${code}_manifest_asset_invalid`)
      && payResult.network === manifest.x402.network
      && address(payResult.payTo, `${code}_payment_pay_to_invalid`) === address(paymentTerms.payTo, `${code}_public_pay_to_invalid`)
      && String(capturedComponent.paymentTransactionHash).toLowerCase() === transactionHash
      && jsonEqual(savedPayment, payBody), `${code}_payment_http_binding_invalid`);

    const retrieveBody = retrieveAction.response;
    const delivery = helpers.projectDeliveryEnvelope({ envelope: retrieveBody,
      expectedResourceId: expected.resourceId, expectedContentHash: resource.resourceSha256,
      provenanceId: resource.provenance.classification });
    must(delivery.projection?.resourceId === expected.resourceId
      && delivery.projection?.contentType === resource.contentType
      && delivery.projection?.contentHash === resource.resourceSha256.toLowerCase()
      && delivery.contentBytesSha256 === resource.resourceSha256.toLowerCase(),
    `${code}_delivery_projection_invalid`);
    const pinned = await helpers.readPinnedResource(resource.resourcePath, resource.resourceSha256);
    must(pinned?.bytes instanceof Uint8Array && sha256(Buffer.from(pinned.bytes)) === resource.resourceSha256.toLowerCase()
      && Buffer.from(retrieveBody.contentBytes, 'base64').equals(Buffer.from(pinned.bytes)),
    `${code}_delivered_bytes_do_not_match_pinned_resource`);
    const contentArtifact = await readArtifact(capturedComponent.deliveredContentArtifact,
      capturedComponent.contentArtifactSha256, byPath, rawArtifact, `${code}_content_artifact`);
    must(contentArtifact.bytes.equals(Buffer.from(pinned.bytes))
      && capturedComponent.validatedContentSha256 === delivery.contentBytesSha256
      && Number(capturedComponent.contentBytes) === pinned.bytes.byteLength,
    `${code}_content_artifact_binding_mismatch`);
    const projectionArtifact = await readArtifact(capturedComponent.deliveryProjectionArtifact,
      byPath.get(capturedComponent.deliveryProjectionArtifact)?.sha256, byPath, rawArtifact, `${code}_delivery_projection_artifact`);
    const savedProjection = record(projectionArtifact.value, `${code}_saved_projection_invalid`);
    must(savedProjection.operationId === payAction.action.operationId
      && savedProjection.resourceId === expected.resourceId && savedProjection.offerId === expected.offerId
      && jsonEqual(savedProjection.projection, delivery.projection)
      && jsonEqual(savedProjection.component, delivery.component)
      && savedProjection.contentBytesSha256 === delivery.contentBytesSha256,
    `${code}_saved_projection_binding_mismatch`);
    const projectedComponent = helpers.component({ componentId: capturedComponent.componentId,
      resourceId: expected.resourceId, validator: delivery.component.validator, sourceIds: delivery.component.sourceIds });
    must(projectedComponent.componentId === capturedComponent.componentId
      && projectedComponent.resourceId === expected.resourceId
      && jsonEqual(projectedComponent.validator, capturedComponent.validator)
      && jsonEqual(projectedComponent.sourceIds, capturedComponent.permittedSources)
      && projectedComponent.sourceIds.includes(resource.provenance.classification),
    `${code}_validator_projection_mismatch`);

    checkOperation(durable, payAction.action.operationId, 'purchase', 'delivered', 'success', transactionHash, `${code}_purchase`);
    const paymentDbRows = array(durable.payments, `${code}_durable_payments_missing`)
      .filter((row) => row?.operation_id === payAction.action.operationId);
    const deliveryDbRows = array(durable.deliveries, `${code}_durable_deliveries_missing`)
      .filter((row) => row?.operation_id === payAction.action.operationId);
    must(paymentDbRows.length === 1 && deliveryDbRows.length === 1, `${code}_durable_payment_or_delivery_missing`);
    const paymentDb = record(paymentDbRows[0], `${code}_durable_payment_invalid`);
    const deliveryDb = record(deliveryDbRows[0], `${code}_durable_delivery_invalid`);
    must(paymentDb.receipt_status === 'success' && String(paymentDb.transaction_hash).toLowerCase() === transactionHash
      && address(paymentDb.payer_address, `${code}_durable_payer_invalid`) === payer
      && String(paymentDb.amount_units) === expected.amountUsdcUnits
      && address(paymentDb.asset_address, `${code}_durable_asset_invalid`) === address(manifest.x402.asset, `${code}_asset_invalid`)
      && paymentDb.network === manifest.x402.network
      && paymentDb.payer_balance_before === (index === 0 ? initialUsdcUnits : (BigInt(initialUsdcUnits)
        - BigInt(profileTask.components.slice(0, index).reduce((sum, item) => sum + BigInt(item.amountUsdcUnits), 0n))).toString())
      && String(deliveryDb.resource_id) === expected.resourceId
      && String(deliveryDb.content_sha256).toLowerCase() === resource.resourceSha256.toLowerCase()
      && String(deliveryDb.content_bytes) === String(pinned.bytes.byteLength),
    `${code}_durable_effect_binding_mismatch`);
    const capturedPayment = record(paymentRows[index], `${code}_payment_action_invalid`);
    must(capturedPayment.operationId === payAction.action.operationId
      && String(capturedPayment.transactionHash).toLowerCase() === transactionHash
      && String(capturedPayment.deliveryContentSha256).toLowerCase() === resource.resourceSha256.toLowerCase(),
    `${code}_payment_action_capture_mismatch`);
    serviceAmounts.push(BigInt(expected.amountUsdcUnits));
    projectedComponents.push(projectedComponent);
    componentRefs.push({ componentId: projectedComponent.componentId, resourceId: expected.resourceId,
      offerId: expected.offerId, amountUsdcUnits: expected.amountUsdcUnits,
      paymentOperationId: payAction.action.operationId, transactionHash,
      payResponse: { path: payAction.action.rawResponsePath, sha256: payAction.action.rawResponseSha256 },
      retrieveResponse: { path: retrieveAction.action.rawResponsePath, sha256: retrieveAction.action.rawResponseSha256 },
      deliveryProjection: { path: projectionArtifact.path, sha256: projectionArtifact.sha256 },
      deliveredContent: { path: contentArtifact.path, sha256: contentArtifact.sha256 },
      contentSha256: resource.resourceSha256.toLowerCase() });
  }

  const obligationRows = array(capture.obligations, 'u1_v2_obligations_missing');
  const transferRows = array(capture.actions?.transfers, 'u1_v2_transfer_actions_missing');
  must(obligationRows.length === EXPECTED_OBLIGATIONS.length && transferRows.length === obligationRows.length,
    'u1_v2_obligation_count_invalid');
  const payoutAssetId = helpers.assetId(identity, manifest.contracts.usdc.address);
  const payoutObligations = [];
  const payoutRefs = [];
  const participantEconomicActions = [];
  for (let index = 0; index < obligationRows.length; index += 1) {
    const obligation = record(obligationRows[index], 'u1_v2_obligation_invalid');
    const expected = profileTask.obligations[index];
    const code = `u1_v2_payout_${index + 1}`;
    const actionIndex = 5 + index;
    const action = await readAction(actions, actionIndex, byPath, rawArtifact);
    const transfer = record(transferRows[index], `${code}_capture_missing`);
    const recipient = address(expected.recipient, `${code}_profile_recipient_invalid`);
    const amount = positiveUint(expected.amountUsdcUnits, `${code}_profile_amount_invalid`);
    must(obligation.obligationId === expected.obligationId && address(obligation.recipient, `${code}_recipient_invalid`) === recipient
      && obligation.amountUsdcUnits === amount && obligation.exactDeltaVerified === true
      && transfer.operationId === action.action.operationId && action.action.kind === 'transfer'
      && transfer.operationId === action.response.operationId,
    `${code}_profile_or_action_binding_mismatch`);
    const response = action.response;
    const actionFacts = participantActionResponse(response, action.action, 'transfer', payer, code);
    const token = address(manifest.contracts.usdc.address, `${code}_usdc_address_invalid`);
    must(address(actionFacts.selected.token, `${code}_selected_token_invalid`) === token
      && address(actionFacts.selected.recipient, `${code}_selected_recipient_invalid`) === recipient
      && String(actionFacts.selected.amountUnits) === amount
      && address(actionFacts.receipt.to, `${code}_receipt_token_invalid`) === token
      && address(actionFacts.transaction.to, `${code}_transaction_token_invalid`) === token,
    `${code}_selected_transfer_binding_mismatch`);
    transferEvent(actionFacts.receipt, token, payer, recipient, amount, code);
    const initialRecipientUnits = uint(initialRecipients[recipient], `${code}_initial_recipient_balance_missing`);
    const finalRecipientUnits = uint(finalRecipients[recipient], `${code}_final_recipient_balance_missing`);
    must(obligation.initialUsdcUnits === initialRecipientUnits
      && obligation.finalUsdcUnits === finalRecipientUnits
      && BigInt(finalRecipientUnits) - BigInt(initialRecipientUnits) === BigInt(amount)
      && BigInt(finalRecipientUnits) === BigInt(initialRecipientUnits) + BigInt(amount)
      && String(transfer.recipient).toLowerCase() === recipient
      && transfer.amountUnits === amount && transfer.transferEventVerified === true
      && String(transfer.transactionHash).toLowerCase() === actionFacts.receipt.transactionHash.toLowerCase()
      && String(transfer.receiptBlockNumber) === String(actionFacts.receipt.blockNumber)
      && String(transfer.receiptBlockHash).toLowerCase() === String(actionFacts.receipt.blockHash).toLowerCase(),
    `${code}_exact_payout_delta_invalid`);
    const rawBefore = record(response.before, `${code}_before_state_missing`);
    const rawAfter = record(response.after, `${code}_after_state_missing`);
    must(uint(rawBefore.recipientUsdcUnits, `${code}_raw_before_recipient_invalid`) === initialRecipientUnits
      && uint(rawAfter.recipientUsdcUnits, `${code}_raw_after_recipient_invalid`) === finalRecipientUnits,
    `${code}_raw_recipient_cutoff_mismatch`);
    checkOperation(durable, action.action.operationId, 'transfer', 'settled', 'success', actionFacts.receipt.transactionHash, code);
    participantEconomicActions.push({ operationId: action.action.operationId, transactionHash: actionFacts.receipt.transactionHash,
      receipt: actionFacts.receipt, kind: 'transfer', actionRef: action.action });
    payoutObligations.push({ obligationId: expected.obligationId, recipient, assetId: payoutAssetId, exactAmountUnits: amount });
    payoutRefs.push({ obligationId: expected.obligationId, recipient, amountUsdcUnits: amount,
      operationId: action.action.operationId,
      transactionHash: String(actionFacts.receipt.transactionHash).toLowerCase(),
      rawResponse: { path: action.action.rawResponsePath, sha256: action.action.rawResponseSha256 } });
  }
  must(jsonEqual(Object.keys(initialRecipients).map((item) => item.toLowerCase()).sort(),
    payoutObligations.map((item) => item.recipient).sort())
    && jsonEqual(Object.keys(finalRecipients).map((item) => item.toLowerCase()).sort(),
      payoutObligations.map((item) => item.recipient).sort()), 'u1_v2_recipient_baseline_inventory_invalid');

  const approveAction = await readAction(actions, 7, byPath, rawArtifact);
  const swapAction = await readAction(actions, 8, byPath, rawArtifact);
  const unwrapAction = await readAction(actions, 9, byPath, rawArtifact);
  const approvalCapture = record(capture.actions?.approval, 'u1_v2_approval_capture_missing');
  const swapCapture = record(capture.actions?.swap, 'u1_v2_swap_capture_missing');
  const unwrapCapture = record(capture.actions?.unwrap, 'u1_v2_unwrap_capture_missing');
  const approval = participantActionResponse(approveAction.response, approveAction.action, 'approve', payer, 'u1_v2_approval');
  const swap = participantActionResponse(swapAction.response, swapAction.action, 'swap', payer, 'u1_v2_swap');
  const unwrap = participantActionResponse(unwrapAction.response, unwrapAction.action, 'unwrap', payer, 'u1_v2_unwrap');
  const expectedInput = EXPECTED_PLANNING.exactInputUsdcUnits;
  const expectedOutput = plan.plannedInput.quotedNativeOutputWei;
  const expectedMinimum = plan.plannedInput.minimumNativeOutputWei;
  const pool = record(manifest.contracts.pool3000, 'u1_v2_pool_missing');
  const usdcAddress = address(manifest.contracts.usdc.address, 'u1_v2_usdc_missing');
  const wethAddress = address(manifest.contracts.weth.address, 'u1_v2_weth_missing');
  must(approveAction.action.kind === 'approve' && swapAction.action.kind === 'swap' && unwrapAction.action.kind === 'unwrap'
    && approvalCapture.operationId === approveAction.action.operationId
    && swapCapture.operationId === swapAction.action.operationId
    && unwrapCapture.operationId === unwrapAction.action.operationId,
  'u1_v2_trade_operation_binding_invalid');
  must(address(approval.selected.token, 'u1_v2_approval_token_invalid') === usdcAddress
    && address(approval.selected.spender, 'u1_v2_approval_spender_invalid') === router
    && String(approval.selected.amountUnits) === expectedInput
    && approvalCapture.amountUnits === expectedInput
    && address(swap.selected.router, 'u1_v2_swap_router_invalid') === router
    && swap.selected.route === 'uniswap-v3-exactInputSingle'
    && address(swap.selected.tokenIn, 'u1_v2_swap_token_in_invalid') === usdcAddress
    && address(swap.selected.tokenOut, 'u1_v2_swap_token_out_invalid') === wethAddress
    && address(swap.selected.poolAddress, 'u1_v2_swap_pool_address_invalid') === address(pool.address, 'u1_v2_pool_address_invalid')
    && String(swap.selected.poolCodeHash).replace(/^0x/i, '').toLowerCase() === String(pool.codeHash).replace(/^0x/i, '').toLowerCase()
    && Number(swap.selected.fee) === EXPECTED_PLANNING.feeTier && String(swap.selected.amountInUnits) === expectedInput
    && String(swap.selected.amountOutMinimumUnits) === expectedMinimum
    && String(swapCapture.amountInUnits) === expectedInput && Number(swapCapture.feeTier) === EXPECTED_PLANNING.feeTier
    && String(swapCapture.observedWethOutputWei) === expectedOutput
    && String(swapCapture.amountOutMinimumWei) === expectedMinimum && String(swapCapture.finalAllowanceUnits) === '0'
    && String(unwrap.selected.amountWei) === expectedOutput
    && String(unwrapCapture.amountWei) === expectedOutput && String(unwrapCapture.finalWethUnits) === '0',
  'u1_v2_approval_swap_or_unwrap_scope_invalid');
  transferEvent(swap.receipt, wethAddress, address(pool.address, 'u1_v2_pool_address_invalid'), payer, expectedOutput, 'u1_v2_swap_weth_output');
  transferEvent(swap.receipt, usdcAddress, payer, address(pool.address, 'u1_v2_pool_address_invalid'), expectedInput, 'u1_v2_swap_usdc_input');
  checkOperation(durable, approveAction.action.operationId, 'approve', 'settled', 'success', approval.receipt.transactionHash, 'u1_v2_approval');
  checkOperation(durable, swapAction.action.operationId, 'swap', 'settled', 'success', swap.receipt.transactionHash, 'u1_v2_swap');
  checkOperation(durable, unwrapAction.action.operationId, 'unwrap', 'settled', 'success', unwrap.receipt.transactionHash, 'u1_v2_unwrap');
  participantEconomicActions.push(
    { operationId: approveAction.action.operationId, transactionHash: approval.receipt.transactionHash, receipt: approval.receipt, kind: 'approve', actionRef: approveAction.action },
    { operationId: swapAction.action.operationId, transactionHash: swap.receipt.transactionHash, receipt: swap.receipt, kind: 'swap', actionRef: swapAction.action },
    { operationId: unwrapAction.action.operationId, transactionHash: unwrap.receipt.transactionHash, receipt: unwrap.receipt, kind: 'unwrap', actionRef: unwrapAction.action },
  );
  const finalNativeWei = uint(finalRaw.payerNativeWei, 'u1_v2_final_native_invalid');
  const finalUsdcUnits = uint(finalRaw.payerUsdcUnits, 'u1_v2_final_usdc_invalid');
  const finalWethUnits = uint(finalRaw.payerWethUnits, 'u1_v2_final_weth_invalid');
  const expectedService = serviceAmounts.reduce((sum, value) => sum + value, 0n);
  const expectedPayout = payoutObligations.reduce((sum, item) => sum + BigInt(item.exactAmountUnits), 0n);
  must(BigInt(finalUsdcUnits) === BigInt(initialUsdcUnits) - expectedService - expectedPayout - BigInt(expectedInput)
    && BigInt(finalWethUnits) === 0n
    && String(finalRaw.blockNumber) === String(unwrap.receipt.blockNumber)
    && String(finalRaw.blockHash).toLowerCase() === String(unwrap.receipt.blockHash).toLowerCase(),
  'u1_v2_final_cutoff_or_balance_mismatch');

  const costRows = array(durable.transactionCosts, 'u1_v2_durable_costs_missing');
  const observedCosts = record(capture.observedCosts, 'u1_v2_observed_costs_missing');
  const capturedReceipts = array(observedCosts.receipts, 'u1_v2_cost_receipts_missing');
  let participantGasWei = 0n;
  const participantOperationIds = new Set(participantEconomicActions.map((item) => item.operationId));
  must(participantOperationIds.size === 5 && participantEconomicActions.length === 5,
    'u1_v2_participant_cost_action_inventory_invalid');
  for (const item of participantEconomicActions) {
    const row = checkCostRow(costRows, capturedReceipts, item.operationId, payer, item.transactionHash, item.receipt,
      capture.manifestSha256, `u1_v2_cost_${item.kind}`);
    participantGasWei += BigInt(row.gas_cost_wei);
  }
  const facilitatorRows = costRows.filter((row) => row?.payer_role === 'facilitator');
  must(facilitatorRows.length === 2
    && costRows.length === participantEconomicActions.length + facilitatorRows.length,
  'u1_v2_facilitator_cost_inventory_invalid');
  for (const row of facilitatorRows) must(row.receipt_status === 'success', 'u1_v2_facilitator_receipt_not_successful');
  must(participantGasWei.toString() === observedCosts.participantGasWei
    && String(observedCosts.serviceChargesUsdcUnits) === expectedService.toString()
    && String(observedCosts.rateNumerator) === manifest.feePolicy.ethUsdcRateNumerator
    && String(observedCosts.rateDenominator) === manifest.feePolicy.ethUsdcRateDenominator,
  'u1_v2_observed_expense_inputs_mismatch');
  const dexFee = ((BigInt(expectedInput) * BigInt(EXPECTED_PLANNING.feeTier) + 999999n) / 1000000n).toString();
  must(String(observedCosts.declaredDexFeeUsdcUnits) === dexFee
    && observedCosts.dexFeeFormula === 'ceil(exactInputUsdcUnits * feeTier / 1000000); reported as declared route expense, not a receipt measurement',
  'u1_v2_dex_fee_policy_mismatch');
  const expenseBudget = helpers.budget(manifest, policy, expectedService.toString(), participantGasWei.toString(), dexFee);
  must(String(observedCosts.participantAggregateGasUsdcUnits) === expenseBudget.gasUsdcUnits,
    'u1_v2_participant_gas_conversion_mismatch');
  const expense = {
    ...expenseBudget,
    serviceChargesUsdcUnits: expectedService.toString(),
    participantGasWei: participantGasWei.toString(),
    participantGasUsdcUnits: expenseBudget.gasUsdcUnits,
    verifiedDexFeeUsdcUnits: dexFee,
    excludedSwapPrincipalUsdcUnits: expectedInput,
    facilitatorGasWeiExcluded: facilitatorRows.reduce((sum, row) => sum + BigInt(uint(row.gas_cost_wei, 'u1_v2_facilitator_gas_invalid')), 0n).toString(),
    principalExcluded: policy.expenseBudget.excludePrincipal,
  };
  must(BigInt(expense.measuredExpenseUsdcUnits) === BigInt(expectedService) + BigInt(expenseBudget.gasUsdcUnits) + BigInt(dexFee)
    && expense.principalExcluded === true, 'u1_v2_expense_breakdown_mismatch');
  must(BigInt(finalNativeWei) === BigInt(initialNativeWei) + BigInt(expectedOutput) - participantGasWei
    && BigInt(finalNativeWei) >= BigInt(plan.nativeReserveWei), 'u1_v2_native_balance_or_reserve_mismatch');

  const rateNumerator = String(plan.plannedInput.ethUsdcRateNumerator);
  const rateDenominator = String(plan.plannedInput.ethUsdcRateDenominator);
  const finalUsdcTarget = shareWithin(finalUsdcUnits, finalNativeWei, rateNumerator, rateDenominator, 40, 1);
  const finalEthTarget = nativeShareWithin(finalUsdcUnits, finalNativeWei, rateNumerator, rateDenominator, 9960, 1);
  must(finalUsdcTarget && finalEthTarget && finalWethUnits === '0', 'u1_v2_actual_allocation_outside_target');
  const actualAllocation = record(finalRaw.allocation, 'u1_v2_allocation_observation_missing');
  must(actualAllocation.USDC?.shareBps === 40 && actualAllocation.USDC?.toleranceBps === 1
    && actualAllocation.ETH?.shareBps === 9960 && actualAllocation.ETH?.toleranceBps === 1
    && actualAllocation.WETH?.balanceUnits === '0' && actualAllocation.WETH?.targetUnits === '0'
    && actualAllocation.WETH?.toleranceUnits === '0' && actualAllocation.USDC?.withinTarget === true
    && actualAllocation.ETH?.withinTarget === true && actualAllocation.WETH?.withinTarget === true,
  'u1_v2_reported_allocation_disagrees_with_independent_projection');

  const routerRoute = helpers.route(manifest, EXPECTED_PLANNING.feeTier, 'forward');
  const initialParticipant = record(helpers.participantState(participantSnapshotInput(initialRaw), router), 'u1_v2_initial_participant_projection_invalid');
  const finalParticipant = record(helpers.participantState(participantSnapshotInput(finalRaw), router), 'u1_v2_final_participant_projection_invalid');
  const recipientBalances = (values, code) => payoutObligations.map((item) => ({
    account: item.recipient, assetId: payoutAssetId,
    amountUnits: uint(values[item.recipient], `${code}_recipient_balance_invalid`),
  }));
  const initial = helpers.state([...array(initialParticipant.balances, 'u1_v2_initial_balances_missing'),
    ...recipientBalances(initialRecipients, 'u1_v2_initial')],
  array(initialParticipant.allowances, 'u1_v2_initial_allowances_missing'), [], []);
  const final = helpers.state([...array(finalParticipant.balances, 'u1_v2_final_balances_missing'),
    ...recipientBalances(finalRecipients, 'u1_v2_final')],
  array(finalParticipant.allowances, 'u1_v2_final_allowances_missing'),
  projectedComponents.map((item) => item.componentId), payoutObligations.map((item) => item.obligationId));
  const allocationAssets = [
    { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 40, toleranceBps: 1 },
    { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: rateNumerator, denominator: rateDenominator }, targetShareBps: 9960, toleranceBps: 1 },
    { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: rateNumerator, denominator: rateDenominator }, targetShareBps: 0, toleranceBps: 0 },
  ];
  const objective = {
    requiredComponents: projectedComponents,
    permittedSources: [...policy.permittedProvenanceIds],
    permittedRoutes: [routerRoute],
    allocationAssets,
    payoutObligations,
    temporarySpenderScope: [{ owner: 'participant', tokenAssetId: expectedPayerId, spender: router }],
    nativeReserveWei: plan.nativeReserveWei,
    expenseBudgetUsdcUnits: expenseBudget.budgetUsdcUnits,
    duplicatePurchaseIdentity: policy.duplicatePurchaseIdentity,
  };
  const relevantPaths = [
    caseArtifact.path, profileArtifact.path, quoteArtifact.path, planFile.path,
    catalogAction.action.rawResponsePath,
    ...componentRefs.flatMap((item) => [item.payResponse.path, item.retrieveResponse.path,
      item.deliveryProjection.path, item.deliveredContent.path]),
    ...payoutRefs.map((item) => item.rawResponse.path),
    approveAction.action.rawResponsePath, swapAction.action.rawResponsePath, unwrapAction.action.rawResponsePath,
  ];
  const rawReferences = [...new Map(relevantPaths.map((path) => {
    const ref = referenceFor(path, byPath);
    return [ref.path, ref];
  })).values()];
  const extraEvidence = {
    schemaVersion: 'bts-u1-v2-candidate-projection-evidence/v1',
    classification: 'retained_local_reference_projection_not_semantic_task_acceptance',
    sourceProfile: { path: profileRef.path, sha256: profileRef.sha256, evidence: { path: profileArtifact.path, sha256: profileArtifact.sha256 } },
    capture: { path: caseArtifact.path, sha256: caseArtifact.sha256 },
    participantToolProtocol: probe.participantToolProtocol,
    participantActions: actions.map((item) => ({ kind: item.kind, operationId: item.operationId,
      rawResponsePath: item.rawResponsePath, rawResponseSha256: item.rawResponseSha256 })),
    catalogRead: { operationId: catalogAction.action.operationId,
      rawResponsePath: catalogAction.action.rawResponsePath, rawResponseSha256: catalogAction.action.rawResponseSha256 },
    paidReferences: componentRefs,
    payoutReferences: payoutRefs,
    preActionPlan: {
      path: planFile.path, sha256: planFile.sha256,
      planningGenerationId: planValidation.planningGenerationId,
      planningGenerationFence: planning.fence,
      publicQuote: { path: quoteArtifact.path, sha256: quoteArtifact.sha256,
        inputAssetId: 'USDC', outputAssetId: 'WETH', amountInUnits: expectedInput,
        amountOutUnits: expectedOutput, minimumOutputUnits: expectedMinimum, feeTier: EXPECTED_PLANNING.feeTier,
        poolAddress: pool.address, poolCodeHash: pool.codeHash,
        quoterAddress: quote.quoterAddress, independentResult: quote.independentResult },
      validation: planValidation,
    },
    route: { routeId: 'fee3000', routeType: 'uniswap_v3_exact_input_single', feeTier: EXPECTED_PLANNING.feeTier,
      tokenInAssetId: 'USDC', tokenOutAssetId: 'WETH', routerContractId: 'swapRouter02', poolContractId: 'pool3000',
      routerAddress: router, poolAddress: pool.address, poolCodeHash: pool.codeHash,
      exactInputUnits: expectedInput, minimumOutputUnits: expectedMinimum, observedOutputUnits: expectedOutput },
    expense: { serviceChargesUsdcUnits: expense.serviceChargesUsdcUnits,
      participantGasWei: expense.participantGasWei, participantGasUsdcUnits: expense.participantGasUsdcUnits,
      dexFeeUsdcUnits: expense.verifiedDexFeeUsdcUnits, excludedSwapPrincipalUsdcUnits: expense.excludedSwapPrincipalUsdcUnits,
      measuredExpenseUsdcUnits: expense.measuredExpenseUsdcUnits, budgetUsdcUnits: expense.budgetUsdcUnits,
      facilitatorGasWeiExcluded: expense.facilitatorGasWeiExcluded },
    generationFence: probe.generationFence,
    rawReferences,
    claims: { taskGrade: false, difficultyApproved: false, releaseActivated: false, acceptanceClaim: false },
  };
  return { initial, final, objective, expense, extraEvidence };
}
