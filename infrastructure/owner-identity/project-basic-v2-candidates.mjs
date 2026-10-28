// Projection of actual S1/S2/S3/S4/M3 v2 captures into TaskCase fields.
// The module is offline: it reads only the pinned capture/resource inputs supplied by the caller.
import { createHash } from 'node:crypto';
import { canonicalTaskJson, sha256CanonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';

const HASH = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH32 = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const ENVELOPE_SCHEMA_SOURCE = 'packages/benchmark-environment/src/probe/task-reference-cases.ts';

function must(condition, code) {
  if (!condition) throw new Error(code);
}

function record(value, code) {
  must(value !== null && typeof value === 'object' && !Array.isArray(value), code);
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

function hash32(value, code) {
  must(typeof value === 'string' && HASH32.test(value), code);
  return value.toLowerCase();
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function jsonEqual(left, right) {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function routerAddress(manifest) {
  return address(manifest.contracts?.swapRouter02?.address, 'basic_v2_router_missing');
}

function participantSnapshot(raw, helpers, router) {
  record(raw, 'basic_v2_state_missing');
  const native = raw.payerNativeEthWei ?? raw.payerNativeWei;
  const usdcAllowance = raw.usdcRouterAllowanceUnits ?? raw.usdcAllowanceUnits;
  const wethAllowance = raw.wethRouterAllowanceUnits ?? raw.wethAllowanceUnits;
  return helpers.state([
    { account: 'participant', assetId: 'ETH', amountUnits: uint(native, 'basic_v2_native_balance_invalid') },
    { account: 'participant', assetId: 'USDC', amountUnits: uint(raw.payerUsdcUnits, 'basic_v2_usdc_balance_invalid') },
    { account: 'participant', assetId: 'WETH', amountUnits: uint(raw.payerWethUnits, 'basic_v2_weth_balance_invalid') },
  ], ['USDC', 'WETH'].map((tokenAssetId) => ({
    owner: 'participant', tokenAssetId, spender: router,
    amountUnits: uint(tokenAssetId === 'USDC' ? usdcAllowance : wethAllowance, 'basic_v2_allowance_invalid'),
  })));
}

function participantAndRecipientSnapshot(raw, helpers, router) {
  record(raw, 'basic_v2_state_missing');
  const payer = address(raw.payerAddress, 'basic_v2_payer_address_invalid');
  const recipient = address(raw.recipientAddress, 'basic_v2_recipient_address_invalid');
  must(payer !== recipient, 'basic_v2_transfer_accounts_overlap');
  return helpers.state([
    { account: 'participant', assetId: 'ETH', amountUnits: uint(raw.payerNativeWei, 'basic_v2_native_balance_invalid') },
    { account: 'participant', assetId: 'USDC', amountUnits: uint(raw.payerUsdcUnits, 'basic_v2_usdc_balance_invalid') },
    { account: 'participant', assetId: 'WETH', amountUnits: uint(raw.payerWethUnits, 'basic_v2_weth_balance_invalid') },
    { account: recipient, assetId: 'USDC', amountUnits: uint(raw.recipientUsdcUnits, 'basic_v2_recipient_usdc_invalid') },
    { account: recipient, assetId: 'WETH', amountUnits: uint(raw.recipientWethUnits, 'basic_v2_recipient_weth_invalid') },
  ], ['USDC', 'WETH'].map((tokenAssetId) => ({
    owner: 'participant', tokenAssetId, spender: router,
    amountUnits: uint(tokenAssetId === 'USDC' ? raw.usdcRouterAllowanceUnits : raw.wethRouterAllowanceUnits,
      'basic_v2_allowance_invalid'),
  })));
}

function canonicalPaymentRequirements(value, identity, helpers) {
  const req = record(value, 'basic_v2_payment_requirements_missing');
  must(typeof req.scheme === 'string' && typeof req.resourceId === 'string' && typeof req.offerId === 'string'
    && typeof req.version === 'string' && typeof req.network === 'string'
    && Array.isArray(req.authFields), 'basic_v2_payment_requirements_invalid');
  return {
    scheme: req.scheme,
    resourceId: req.resourceId,
    offerId: req.offerId,
    version: req.version,
    amountUnits: positiveUint(req.amountUnits, 'basic_v2_payment_amount_invalid'),
    network: req.network,
    assetId: helpers.assetId(identity, req.assetId),
    recipient: address(req.recipient, 'basic_v2_payment_recipient_invalid'),
    authFields: req.authFields.map((field) => {
      const item = record(field, 'basic_v2_auth_field_invalid');
      must(typeof item.name === 'string' && typeof item.value === 'string', 'basic_v2_auth_field_invalid');
      return { name: item.name, value: item.value };
    }),
  };
}

function captureActions(probe, expectedKinds) {
  const actions = probe.captureReferences?.participantActions;
  must(Array.isArray(actions) && actions.length === expectedKinds.length
    && probe.participantActionCount === expectedKinds.length, 'basic_v2_action_count_invalid');
  const projectedActions = probe.capture?.participantActions;
  must(Array.isArray(projectedActions) && projectedActions.length === actions.length,
    'basic_v2_capture_action_trace_missing');
  return actions.map((action, index) => {
    record(action, 'basic_v2_action_invalid');
    const projected = record(projectedActions[index], 'basic_v2_capture_action_invalid');
    must(action.kind === expectedKinds[index] && projected.kind === expectedKinds[index]
      && action.operationId === projected.operationId && action.rawResponsePath === projected.rawResponsePath
      && action.rawResponseSha256 === projected.rawResponseSha256 && HASH.test(action.rawResponseSha256),
    'basic_v2_action_binding_mismatch');
    return action;
  });
}

async function readAction(rawArtifact, action) {
  must(typeof rawArtifact === 'function', 'basic_v2_raw_artifact_reader_missing');
  const input = await rawArtifact(action.rawResponsePath);
  must(input && input.bytes instanceof Uint8Array && sha256(input.bytes) === action.rawResponseSha256,
    'basic_v2_action_response_hash_mismatch');
  const value = record(input.value, 'basic_v2_action_response_invalid');
  must(value.operationId === action.operationId, 'basic_v2_action_response_operation_mismatch');
  return value;
}

function sameBlock(left, right, code) {
  record(left, code);
  record(right, code);
  must(String(left.number ?? left.blockNumber) === String(right.number ?? right.blockNumber)
    && hash32(left.hash ?? left.blockHash, code) === hash32(right.hash ?? right.blockHash, code), code);
}

function canonicalCatalogOffers(identity, offers, helpers) {
  must(Array.isArray(offers), 'basic_v2_catalog_offers_invalid');
  return offers.map((offer) => {
    record(offer, 'basic_v2_catalog_offer_invalid');
    const payment = record(offer.paymentRequirements, 'basic_v2_catalog_payment_invalid');
    return { ...offer, assetId: helpers.assetId(identity, offer.assetId),
      paymentRequirements: { ...payment, assetId: helpers.assetId(identity, payment.assetId) } };
  });
}

function zeroEffectCounts(counts, code) {
  record(counts, code);
  for (const [key, value] of Object.entries(counts)) {
    must(String(value) === '0', code);
  }
}

function projectionForS1(probe, helpers, manifest, policy, rawResponse) {
  const capture = probe.capture;
  const before = record(capture.before, 'basic_v2_s1_before_missing');
  const after = record(capture.after, 'basic_v2_s1_after_missing');
  const action = record(capture.action, 'basic_v2_s1_action_missing');
  const operation = record(capture.operation, 'basic_v2_s1_operation_missing');
  must(operation.status === 'settled' && operation.receiptStatus === 'success'
    && String(action.token).toLowerCase() === String(manifest.contracts?.usdc?.address).toLowerCase(),
  'basic_v2_s1_transfer_not_settled');
  const principal = positiveUint(action.amountUnits, 'basic_v2_s1_amount_invalid');
  const nativeReserveWei = positiveUint(policy.nativeReserveWei?.S1, 'basic_v2_s1_reserve_missing');
  const gasCostWei = uint(capture.receipt?.gasCostWei, 'basic_v2_s1_gas_cost_missing');
  const selectedAction = record(rawResponse.selectedAction, 'basic_v2_s1_raw_action_missing');
  must(selectedAction.kind === 'transfer' && rawResponse.receipt?.status === 'success'
    && address(selectedAction.token, 'basic_v2_s1_raw_token_invalid') === address(action.token, 'basic_v2_s1_token_invalid')
    && uint(selectedAction.amountUnits, 'basic_v2_s1_raw_amount_invalid') === principal
    && address(selectedAction.recipient, 'basic_v2_s1_raw_recipient_invalid') === address(action.recipient, 'basic_v2_s1_recipient_invalid')
    && hash32(rawResponse.receipt?.transactionHash, 'basic_v2_s1_raw_transaction_invalid')
      === hash32(operation.transactionHash, 'basic_v2_s1_transaction_invalid')
    && uint(rawResponse.receipt?.gasCostWei, 'basic_v2_s1_raw_gas_invalid') === gasCostWei,
  'basic_v2_s1_raw_action_binding_mismatch');
  must(BigInt(before.payerUsdcUnits) - BigInt(after.payerUsdcUnits) === BigInt(principal)
    && BigInt(after.recipientUsdcUnits) - BigInt(before.recipientUsdcUnits) === BigInt(principal)
    && BigInt(before.payerNativeWei) - BigInt(after.payerNativeWei) === BigInt(gasCostWei)
    && BigInt(before.payerNativeWei) >= BigInt(nativeReserveWei)
    && BigInt(after.payerNativeWei) >= BigInt(nativeReserveWei)
    && before.payerWethUnits === after.payerWethUnits && before.recipientWethUnits === after.recipientWethUnits
    && before.poolUsdcUnits === after.poolUsdcUnits && before.poolWethUnits === after.poolWethUnits
    && before.usdcRouterAllowanceUnits === after.usdcRouterAllowanceUnits
    && before.wethRouterAllowanceUnits === after.wethRouterAllowanceUnits,
  'basic_v2_s1_observed_delta_mismatch');
  const unrelated = {
    payerNativeWei: uint(before.payerNativeWei, 'basic_v2_s1_native_invalid'),
    payerWethUnits: uint(before.payerWethUnits, 'basic_v2_s1_weth_invalid'),
    recipientWethUnits: uint(before.recipientWethUnits, 'basic_v2_s1_recipient_weth_invalid'),
    poolUsdcUnits: uint(before.poolUsdcUnits, 'basic_v2_s1_pool_usdc_invalid'),
    poolWethUnits: uint(before.poolWethUnits, 'basic_v2_s1_pool_weth_invalid'),
    usdcRouterAllowanceUnits: uint(before.usdcRouterAllowanceUnits, 'basic_v2_s1_usdc_allowance_invalid'),
    wethRouterAllowanceUnits: uint(before.wethRouterAllowanceUnits, 'basic_v2_s1_weth_allowance_invalid'),
  };
  return {
    initial: participantAndRecipientSnapshot(before, helpers, routerAddress(manifest)),
    final: participantAndRecipientSnapshot(after, helpers, routerAddress(manifest)),
    objective: {
      tokenAssetId: 'USDC', sender: 'participant', recipient: address(action.recipient, 'basic_v2_s1_recipient_invalid'),
      exactPrincipalUnits: principal, nativeReserveWei,
      unrelatedEffectBaselineSha256: sha256CanonicalTaskJson(unrelated),
    },
    expense: null,
  };
}

function projectionForS2(probe, helpers, manifest, identity, rawOffer) {
  const capture = probe.capture;
  const interval = record(capture.noEffectInterval, 'basic_v2_s2_interval_missing');
  const beforeBlock = record(interval.blockBefore, 'basic_v2_s2_before_block_missing');
  const afterBlock = record(interval.blockAfterGet, 'basic_v2_s2_after_block_missing');
  sameBlock(beforeBlock, afterBlock, 'basic_v2_s2_state_block_changed');
  sameBlock(beforeBlock, interval.blockAtEnd, 'basic_v2_s2_state_block_changed');
  const initial = participantSnapshot(interval.stateBefore, helpers, routerAddress(manifest));
  const final = participantSnapshot(interval.stateAfter, helpers, routerAddress(manifest));
  must(jsonEqual(initial, final), 'basic_v2_s2_participant_state_changed');
  zeroEffectCounts(interval.effectCountsBefore, 'basic_v2_s2_pre_effects_not_zero');
  zeroEffectCounts(interval.effectCountsAfter, 'basic_v2_s2_post_effects_not_zero');
  const read = record(capture.offer, 'basic_v2_s2_offer_missing');
  const operation = record(interval.offerReadOperation, 'basic_v2_s2_offer_operation_missing');
  const candidate = record(capture.objectiveCandidate, 'basic_v2_s2_objective_missing');
  must(jsonEqual(rawOffer, read) && read.operationId === operation.operationId && operation.operationKind === 'offer'
    && operation.status === 'accepted' && operation.receiptStatus === 'not_submitted'
    && read.freeInspection === true && read.deliveryState === 'not_delivered'
    && candidate.resourceId === read.resourceId,
  'basic_v2_s2_offer_not_bound');
  const requirements = canonicalPaymentRequirements(candidate.completePaymentRequirements, identity, helpers);
  must(candidate.offerId === requirements.offerId && candidate.resourceId === requirements.resourceId,
    'basic_v2_s2_answer_identity_mismatch');
  const x402 = record(manifest.x402, 'basic_v2_s2_manifest_x402_missing');
  const pinnedResource = x402.catalog?.find((resource) => resource.resourceId === candidate.resourceId);
  const pinnedOffer = pinnedResource?.offers?.find((offer) => offer.id === candidate.offerId);
  const payment = record(read.payment, 'basic_v2_s2_offer_payment_missing');
  const offeredRow = read.offers?.find((offer) => offer.id === candidate.offerId);
  const offeredPayment = record(offeredRow?.payment, 'basic_v2_s2_offer_row_payment_missing');
  const expectedAuthFields = [
    { name: 'assetTransferMethod', value: x402.assetTransferMethod },
    { name: 'paymentFlow', value: 'authorization' },
    { name: 'name', value: x402.eip712Domain?.name },
    { name: 'version', value: x402.eip712Domain?.version },
  ];
  must(pinnedResource && pinnedOffer && read.resourceSha256 === pinnedResource.resourceSha256
    && read.contentType === pinnedResource.contentType && read.schema === pinnedResource.schema
    && read.dataType === (pinnedResource.dataType ?? '') && jsonEqual(read.provenance, pinnedResource.provenance)
    && pinnedOffer.amount === payment.amount && payment.amount === requirements.amountUnits
    && requirements.version === x402.eip712Domain?.version
    && offeredPayment.amount === payment.amount && offeredPayment.scheme === payment.scheme
    && offeredPayment.network === payment.network && offeredPayment.asset.toLowerCase() === payment.asset.toLowerCase()
    && offeredPayment.payTo.toLowerCase() === payment.payTo.toLowerCase()
    && offeredPayment.transferMethod === payment.transferMethod
    && payment.scheme === x402.scheme && payment.network === x402.network
    && String(payment.asset).toLowerCase() === String(x402.asset).toLowerCase()
    && payment.transferMethod === x402.assetTransferMethod
    && address(payment.payTo, 'basic_v2_s2_pay_to_invalid') === requirements.recipient
    && jsonEqual(requirements.authFields, expectedAuthFields), 'basic_v2_s2_payment_manifest_mismatch');
  const requiredAnswerFields = [...new Set(candidate.requiredAnswerFields)];
  must(requiredAnswerFields.length > 0 && requiredAnswerFields.every((field) => typeof field === 'string'),
    'basic_v2_s2_required_fields_invalid');
  const expectedFields = [...new Set(['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId',
    'version', ...requirements.authFields.map((field) => field.name)])];
  must(jsonEqual([...requiredAnswerFields].sort(), [...expectedFields].sort()), 'basic_v2_s2_required_fields_incomplete');
  return {
    initial, final,
    objective: { resourceId: candidate.resourceId, offerId: candidate.offerId,
      completePaymentRequirements: requirements, requiredAnswerFields },
    expense: null,
  };
}

function manifestResourceMap(manifest) {
  const definitions = manifest.x402?.catalog;
  must(Array.isArray(definitions) && definitions.length > 0, 'basic_v2_s3_manifest_catalog_missing');
  const result = new Map();
  for (const definition of definitions) {
    record(definition, 'basic_v2_s3_manifest_resource_invalid');
    must(typeof definition.resourceId === 'string' && HASH.test(definition.resourceSha256)
      && typeof definition.resourcePath === 'string' && definition.contentType === 'application/json'
      && typeof definition.schema === 'string' && Array.isArray(definition.offers)
      && !result.has(definition.resourceId), 'basic_v2_s3_manifest_resource_invalid');
    result.set(definition.resourceId, definition);
  }
  return result;
}

function compareCatalogToManifest({ catalogProjection, rawResponse, candidateOffers, manifest, resourceMap }) {
  record(catalogProjection, 'basic_v2_s3_catalog_projection_missing');
  record(rawResponse, 'basic_v2_s3_catalog_response_missing');
  must(rawResponse.freeInspection === true && rawResponse.deliveryState === 'not_delivered'
    && Array.isArray(rawResponse.catalog) && rawResponse.catalog.length === resourceMap.size
    && Array.isArray(catalogProjection.resources) && catalogProjection.resources.length === resourceMap.size
    && Array.isArray(catalogProjection.offers) && Array.isArray(candidateOffers)
    && jsonEqual(catalogProjection.offers, candidateOffers), 'basic_v2_s3_catalog_scope_invalid');

  const rawResources = new Map();
  for (const raw of rawResponse.catalog) {
    record(raw, 'basic_v2_s3_raw_resource_invalid');
    must(typeof raw.resourceId === 'string' && !rawResources.has(raw.resourceId), 'basic_v2_s3_raw_resource_invalid');
    rawResources.set(raw.resourceId, raw);
  }
  const projectionResources = new Map();
  for (const projected of catalogProjection.resources) {
    record(projected, 'basic_v2_s3_projected_resource_invalid');
    must(typeof projected.resourceId === 'string' && !projectionResources.has(projected.resourceId),
      'basic_v2_s3_projected_resource_invalid');
    projectionResources.set(projected.resourceId, projected);
  }

  const flattened = [];
  for (const [resourceId, definition] of resourceMap) {
    const raw = rawResources.get(resourceId);
    const projected = projectionResources.get(resourceId);
    const resourceHash = catalogProjection.resourceHashes?.[resourceId];
    must(raw && projected && raw.resourceSha256 === definition.resourceSha256
      && resourceHash === definition.resourceSha256 && projected.resourceSha256 === definition.resourceSha256
      && raw.contentType === definition.contentType && projected.contentType === definition.contentType
      && raw.schema === definition.schema && projected.schema === definition.schema
      && jsonEqual(raw.provenance, definition.provenance) && jsonEqual(projected.provenance, definition.provenance)
      && raw.dataType === (definition.dataType ?? '') && projected.dataType === (definition.dataType ?? '')
      && Array.isArray(raw.offers) && raw.offers.length === definition.offers.length
      && Array.isArray(projected.offers) && projected.offers.length === definition.offers.length,
    'basic_v2_s3_catalog_manifest_mismatch');
    const projectedOffersById = new Map(projected.offers.map((offer) => [offer.offerId, offer]));
    for (const [index, pinnedOffer] of definition.offers.entries()) {
      const rawOffer = record(raw.offers[index], 'basic_v2_s3_raw_offer_invalid');
      const payment = record(rawOffer.payment, 'basic_v2_s3_raw_payment_invalid');
      const projectedOffer = record(projectedOffersById.get(pinnedOffer.id), 'basic_v2_s3_projected_offer_missing');
      const paymentRequirements = record(projectedOffer.paymentRequirements, 'basic_v2_s3_payment_requirements_missing');
      const expectedAuthFields = [
        { name: 'assetTransferMethod', value: manifest.x402.assetTransferMethod },
        { name: 'paymentFlow', value: 'authorization' },
        { name: 'name', value: manifest.x402.eip712Domain?.name },
        { name: 'version', value: manifest.x402.eip712Domain?.version },
      ];
      must(rawOffer.id === pinnedOffer.id && payment.amount === pinnedOffer.amount
        && payment.scheme === manifest.x402.scheme && payment.network === manifest.x402.network
        && String(payment.asset).toLowerCase() === String(manifest.x402.asset).toLowerCase()
        && payment.transferMethod === manifest.x402.assetTransferMethod
        && projectedOffer.resourceId === resourceId && projectedOffer.offerId === pinnedOffer.id
        && projectedOffer.dataType === (definition.dataType ?? '')
        && projectedOffer.advertisedTotalPriceUsdcUnits === pinnedOffer.amount
        && projectedOffer.network === payment.network
        && String(projectedOffer.assetId).toLowerCase() === String(payment.asset).toLowerCase()
        && address(projectedOffer.recipient, 'basic_v2_s3_recipient_invalid') === address(payment.payTo, 'basic_v2_s3_pay_to_invalid')
        && paymentRequirements.scheme === payment.scheme && paymentRequirements.resourceId === resourceId
        && paymentRequirements.offerId === pinnedOffer.id && paymentRequirements.amountUnits === pinnedOffer.amount
        && paymentRequirements.network === payment.network
        && String(paymentRequirements.assetId).toLowerCase() === String(payment.asset).toLowerCase()
        && paymentRequirements.version === manifest.x402.eip712Domain.version
        && address(paymentRequirements.recipient, 'basic_v2_s3_payment_recipient_invalid') === address(payment.payTo, 'basic_v2_s3_pay_to_invalid')
        && jsonEqual(paymentRequirements.authFields, expectedAuthFields),
      'basic_v2_s3_catalog_offer_mismatch');
      flattened.push(projectedOffer);
    }
  }
  must(flattened.length === candidateOffers.length
    && new Set(candidateOffers.map((offer) => offer.offerId)).size === candidateOffers.length,
  'basic_v2_s3_catalog_offer_inventory_invalid');
}

async function staticValidator(definition, helpers) {
  const pinned = await helpers.readPinnedResource(definition.resourcePath, definition.resourceSha256);
  must(pinned && pinned.bytes instanceof Uint8Array && sha256(pinned.bytes) === definition.resourceSha256.toLowerCase(),
    'basic_v2_s3_resource_hash_mismatch');
  let content;
  try { content = JSON.parse(Buffer.from(pinned.bytes).toString('utf8')); }
  catch { throw new Error('basic_v2_s3_resource_json_invalid'); }
  must(content.resourceId === definition.resourceId && content.schema === definition.schema
    && (content.provenance === undefined || jsonEqual(content.provenance, definition.provenance))
    && typeof definition.provenance?.classification === 'string', 'basic_v2_s3_resource_manifest_mismatch');
  return {
    validator: {
      validatorVersion: 'bef-delivery-envelope-validator/v1',
      payloadSchemaVersion: 'bef-delivery-envelope/v1',
      requiredFields: [
        { name: 'resourceId', type: 'string' },
        { name: 'contentType', type: 'string' },
        { name: 'contentHash', type: 'sha256' },
        { name: 'contentBytes', type: 'string' },
      ],
      additionalProperties: false,
      predicates: [
        { op: 'equals', field: 'resourceId', value: definition.resourceId },
        { op: 'equals', field: 'contentType', value: definition.contentType },
        { op: 'equals', field: 'contentHash', value: definition.resourceSha256.toLowerCase() },
      ],
      permittedProvenance: [definition.provenance.classification],
    },
    resourceInput: { path: definition.resourcePath, sha256: definition.resourceSha256.toLowerCase(),
      resourceId: definition.resourceId, schema: definition.schema,
      provenanceClassification: definition.provenance.classification },
  };
}

async function projectionForS3(probe, helpers, manifest, identity, policy, rawArtifact) {
  const capture = probe.capture;
  const action = captureActions(probe, ['inspect_catalog'])[0];
  const rawResponse = await readAction(rawArtifact, action);
  const catalogRead = record(capture.publicCatalog, 'basic_v2_s3_public_catalog_missing');
  must(catalogRead.operationId === action.operationId && catalogRead.rawResponsePath === action.rawResponsePath
    && catalogRead.rawResponseSha256 === action.rawResponseSha256, 'basic_v2_s3_catalog_action_binding_mismatch');
  const candidate = record(capture.objectiveCandidate, 'basic_v2_s3_objective_missing');
  const projection = record(catalogRead.response, 'basic_v2_s3_catalog_projection_missing');
  const resourceMap = manifestResourceMap(manifest);
  compareCatalogToManifest({ catalogProjection: projection, rawResponse, candidateOffers: candidate.catalogOffers,
    manifest, resourceMap });

  const validators = new Map();
  const resourceInputs = [];
  for (const [resourceId, definition] of resourceMap) {
    const projected = await staticValidator(definition, helpers);
    validators.set(resourceId, projected.validator);
    resourceInputs.push(projected.resourceInput);
  }
  const catalogOffers = canonicalCatalogOffers(identity, candidate.catalogOffers, helpers).map((offer) => {
    const deliveryValidator = validators.get(offer.resourceId);
    must(deliveryValidator, 'basic_v2_s3_static_validator_missing');
    return { ...offer, deliveryValidator };
  });
  const required = record(candidate.required, 'basic_v2_s3_required_predicate_missing');
  const requiredMax = positiveUint(required.maxAdvertisedTotalPriceUsdcUnits, 'basic_v2_s3_required_max_invalid');
  const requiredAsset = helpers.assetId(identity, required.assetId);
  const requiredRecipient = address(required.recipient, 'basic_v2_s3_required_recipient_invalid');
  must(typeof required.requiredDataType === 'string' && typeof required.network === 'string'
    && required.network === manifest.x402.network && requiredAsset === helpers.assetId(identity, manifest.x402.asset)
    && catalogOffers.some((offer) => offer.dataType === required.requiredDataType
      && BigInt(offer.advertisedTotalPriceUsdcUnits) <= BigInt(requiredMax)
      && offer.network === required.network && offer.assetId === requiredAsset
      && address(offer.recipient, 'basic_v2_s3_offer_recipient_invalid') === requiredRecipient)
    && catalogOffers.some((offer) => !(offer.dataType === required.requiredDataType
      && BigInt(offer.advertisedTotalPriceUsdcUnits) <= BigInt(requiredMax)
      && offer.network === required.network && offer.assetId === requiredAsset
      && address(offer.recipient, 'basic_v2_s3_offer_recipient_invalid') === requiredRecipient)),
    'basic_v2_s3_required_predicate_invalid');
  const initial = participantSnapshot(capture.initialState, helpers, routerAddress(manifest));
  const final = participantSnapshot(capture.finalState, helpers, routerAddress(manifest));
  must(jsonEqual(initial, final), 'basic_v2_s3_participant_state_changed');
  const initialDb = record(capture.initialDatabaseCounts, 'basic_v2_s3_initial_db_counts_missing');
  const finalDb = record(capture.durableDatabase, 'basic_v2_s3_final_db_missing');
  must(String(initialDb.operations) === '0' && String(initialDb.payments) === '0' && String(initialDb.deliveries) === '0'
    && String(finalDb.counts?.operations) === '1' && String(finalDb.counts?.payments) === '0'
    && String(finalDb.counts?.deliveries) === '0' && String(finalDb.counts?.denials) === '0'
    && String(finalDb.counts?.transactionCosts) === '0'
    && Array.isArray(finalDb.operations) && finalDb.operations.length === 1
    && String(finalDb.operations[0].operation_id) === action.operationId
    && finalDb.operations[0].operation_kind === 'catalog' && finalDb.operations[0].status === 'accepted'
    && finalDb.operations[0].receipt_status === 'not_submitted', 'basic_v2_s3_read_only_database_boundary_invalid');
  const expense = null;
  return {
    initial, final,
    objective: {
      catalog: catalogOffers,
      required: { ...required, assetId: requiredAsset, maxAdvertisedTotalPriceUsdcUnits: requiredMax, recipient: requiredRecipient },
    },
    expense,
    extraEvidence: {
      validatorBasis: {
        classification: 'static_pinned_manifest_resource_and_reviewed_envelope_schema_not_observed_delivery',
        validatorVersion: 'bef-delivery-envelope-validator/v1',
        payloadSchemaVersion: 'bef-delivery-envelope/v1',
        sourcePath: ENVELOPE_SCHEMA_SOURCE,
      },
      resourceInputs,
    },
  };
}

async function projectionForS4(probe, helpers, manifest, rawArtifact) {
  const capture = probe.capture;
  const actions = captureActions(probe, ['revoke']);
  const revokeAction = actions[0];
  const revokeResponse = await readAction(rawArtifact, revokeAction);
  must(revokeResponse.outcome === 'success', 'basic_v2_s4_revoke_not_successful');
  const reference = record(capture.referenceCapture, 'basic_v2_s4_reference_capture_missing');
  const setup = record(capture.fixtureSetup, 'basic_v2_s4_fixture_setup_missing');
  const native = record(reference.fixtureSetup, 'basic_v2_s4_reference_fixture_setup_missing');
  const fixtureStage = capture.fixtureStageEvidence;
  must(Array.isArray(fixtureStage) && fixtureStage.length === 1, 'basic_v2_s4_fixture_stage_evidence_missing');
  const fixtureAction = record(fixtureStage[0], 'basic_v2_s4_fixture_stage_action_invalid');
  must(fixtureAction.kind === 'fixture_setup_approve' && fixtureAction.operationId === setup.operationId
    && setup.operationId === native.operationId && fixtureAction.rawResponsePath === setup.rawResponsePath
    && fixtureAction.rawResponseSha256 === setup.rawResponseSha256 && setup.outsideTaskPath === true
    && setup.outsideParticipantPath === true && native.outsideTaskPath === true,
  'basic_v2_s4_fixture_stage_binding_mismatch');
  const setupResponse = await readAction(rawArtifact, fixtureAction);
  const snapshots = record(reference.snapshots, 'basic_v2_s4_snapshots_missing');
  const beforeSetup = record(snapshots.beforeSetup, 'basic_v2_s4_before_setup_missing');
  const start = record(snapshots.taskStartAfterSetup, 'basic_v2_s4_task_start_missing');
  const end = record(snapshots.finalAfterRevoke, 'basic_v2_s4_final_state_missing');
  const candidate = record(reference.objectiveCandidate, 'basic_v2_s4_objective_missing');
  const targetAmount = positiveUint(candidate.taskStartAllowanceUnits, 'basic_v2_s4_initial_allowance_invalid');
  const router = routerAddress(manifest);
  const token = address(manifest.contracts?.usdc?.address, 'basic_v2_s4_usdc_missing');
  const setupReceipt = record(setupResponse.receipt, 'basic_v2_s4_fixture_receipt_missing');
  const setupAction = record(setupResponse.selectedAction, 'basic_v2_s4_fixture_selected_action_missing');
  const setupPersistedCost = record(setup.persistedCost, 'basic_v2_s4_fixture_cost_missing');
  must(setupResponse.outcome === 'success' && setupResponse.operationId === setup.operationId
    && String(setupAction.kind) === 'approve' && String(setupAction.tokenAssetId) === 'USDC'
    && address(setupAction.token, 'basic_v2_s4_fixture_token_invalid') === token
    && address(setupAction.spender, 'basic_v2_s4_fixture_spender_invalid') === router
    && uint(setupAction.amountUnits, 'basic_v2_s4_fixture_amount_invalid') === targetAmount
    && setupReceipt.status === 'success'
    && uint(setupReceipt.gasCostWei, 'basic_v2_s4_fixture_gas_invalid') === uint(setup.gasCostWei, 'basic_v2_s4_fixture_gas_invalid')
    && setupPersistedCost.operation_id === setup.operationId && setupPersistedCost.payer_role === 'participant'
    && setupPersistedCost.receipt_status === 'success' && setupPersistedCost.transaction_hash === setup.transactionHash
    && uint(setupPersistedCost.gas_cost_wei, 'basic_v2_s4_fixture_persisted_gas_invalid') === uint(setup.gasCostWei, 'basic_v2_s4_fixture_gas_invalid')
    && hash32(setupReceipt.transactionHash, 'basic_v2_s4_fixture_tx_invalid') === hash32(setup.transactionHash, 'basic_v2_s4_fixture_tx_invalid')
    && hash32(setupReceipt.blockHash, 'basic_v2_s4_fixture_block_invalid') === hash32(start.blockHash, 'basic_v2_s4_start_block_invalid')
    && String(setupReceipt.blockNumber) === String(start.blockNumber)
    && String(setupResponse.after?.blockNumber) === String(start.blockNumber)
    && uint(setupResponse.before?.usdcRouterAllowance, 'basic_v2_s4_fixture_before_allowance_invalid') === '0'
    && uint(setupResponse.before?.payerNativeWei, 'basic_v2_s4_fixture_before_native_invalid') === uint(beforeSetup.payerNativeWei, 'basic_v2_s4_pre_native_invalid')
    && uint(setupResponse.before?.payerUsdcUnits, 'basic_v2_s4_fixture_before_usdc_invalid') === uint(beforeSetup.payerUsdcUnits, 'basic_v2_s4_pre_usdc_invalid')
    && uint(setupResponse.before?.payerWethUnits, 'basic_v2_s4_fixture_before_weth_invalid') === uint(beforeSetup.payerWethUnits, 'basic_v2_s4_pre_weth_invalid')
    && uint(setupResponse.before?.wethRouterAllowance, 'basic_v2_s4_fixture_before_weth_allowance_invalid') === uint(beforeSetup.wethAllowanceUnits, 'basic_v2_s4_pre_weth_allowance_invalid')
    && uint(start.usdcAllowanceUnits, 'basic_v2_s4_start_allowance_invalid') === targetAmount
    && uint(setupResponse.after?.usdcRouterAllowance, 'basic_v2_s4_fixture_after_allowance_invalid') === targetAmount
    && uint(setupResponse.after?.payerNativeWei, 'basic_v2_s4_fixture_after_native_invalid') === uint(start.payerNativeWei, 'basic_v2_s4_start_native_invalid')
    && uint(setupResponse.after?.payerUsdcUnits, 'basic_v2_s4_fixture_after_usdc_invalid') === uint(start.payerUsdcUnits, 'basic_v2_s4_start_usdc_invalid')
    && uint(setupResponse.after?.payerWethUnits, 'basic_v2_s4_fixture_after_weth_invalid') === uint(start.payerWethUnits, 'basic_v2_s4_start_weth_invalid')
    && uint(setupResponse.after?.wethRouterAllowance, 'basic_v2_s4_fixture_after_weth_allowance_invalid') === uint(start.wethAllowanceUnits, 'basic_v2_s4_start_weth_allowance_invalid')
    && uint(setupResponse.before?.recipientUsdcUnits, 'basic_v2_s4_fixture_before_recipient_usdc_invalid') === uint(setupResponse.after?.recipientUsdcUnits, 'basic_v2_s4_fixture_after_recipient_usdc_invalid')
    && uint(setupResponse.before?.recipientWethUnits, 'basic_v2_s4_fixture_before_recipient_weth_invalid') === uint(setupResponse.after?.recipientWethUnits, 'basic_v2_s4_fixture_after_recipient_weth_invalid')
    && uint(beforeSetup.usdcAllowanceUnits, 'basic_v2_s4_pre_allowance_invalid') === '0',
  'basic_v2_s4_fixture_setup_state_mismatch');
  must(BigInt(beforeSetup.payerNativeWei) - BigInt(start.payerNativeWei) === BigInt(setup.gasCostWei)
    && beforeSetup.payerUsdcUnits === start.payerUsdcUnits && beforeSetup.payerWethUnits === start.payerWethUnits
    && beforeSetup.wethAllowanceUnits === start.wethAllowanceUnits
    && beforeSetup.poolUsdcUnits === start.poolUsdcUnits && beforeSetup.poolWethUnits === start.poolWethUnits,
  'basic_v2_s4_fixture_setup_unrelated_effect');
  const taskPath = record(reference.taskPath, 'basic_v2_s4_task_path_missing');
  const revokeActionBody = record(revokeResponse.selectedAction, 'basic_v2_s4_revoke_action_missing');
  const revokeReceipt = record(revokeResponse.receipt, 'basic_v2_s4_revoke_receipt_missing');
  const persistedCost = record(taskPath.persistedCost, 'basic_v2_s4_revoke_cost_missing');
  const revokeGas = uint(taskPath.gasCostWei, 'basic_v2_s4_revoke_gas_invalid');
  must(revokeResponse.operationId === revokeAction.operationId && revokeActionBody.kind === 'approve'
    && revokeActionBody.tokenAssetId === 'USDC'
    && address(revokeActionBody.token, 'basic_v2_s4_revoke_token_invalid') === token
    && address(revokeActionBody.spender, 'basic_v2_s4_revoke_spender_invalid') === router
    && uint(revokeActionBody.amountUnits, 'basic_v2_s4_revoke_amount_invalid') === '0'
    && revokeReceipt.status === 'success'
    && hash32(revokeReceipt.transactionHash, 'basic_v2_s4_revoke_tx_invalid') === hash32(taskPath.transactionHash, 'basic_v2_s4_task_revoke_tx_invalid')
    && hash32(revokeReceipt.blockHash, 'basic_v2_s4_revoke_block_invalid') === hash32(end.blockHash, 'basic_v2_s4_final_block_invalid')
    && String(revokeReceipt.blockNumber) === String(end.blockNumber)
    && uint(revokeReceipt.gasCostWei, 'basic_v2_s4_revoke_receipt_gas_invalid') === revokeGas
    && persistedCost.operation_id === revokeAction.operationId && persistedCost.payer_role === 'participant'
    && persistedCost.receipt_status === 'success' && persistedCost.transaction_hash === taskPath.transactionHash
    && uint(persistedCost.gas_cost_wei, 'basic_v2_s4_persisted_revoke_gas_invalid') === revokeGas
    && uint(revokeResponse.before?.usdcRouterAllowance, 'basic_v2_s4_revoke_before_allowance_invalid') === targetAmount
    && uint(revokeResponse.after?.usdcRouterAllowance, 'basic_v2_s4_revoke_after_allowance_invalid') === '0'
    && uint(revokeResponse.before?.payerUsdcUnits, 'basic_v2_s4_revoke_before_usdc_invalid') === uint(start.payerUsdcUnits, 'basic_v2_s4_start_usdc_invalid')
    && uint(revokeResponse.after?.payerUsdcUnits, 'basic_v2_s4_revoke_after_usdc_invalid') === uint(end.payerUsdcUnits, 'basic_v2_s4_final_usdc_invalid')
    && uint(revokeResponse.before?.payerNativeWei, 'basic_v2_s4_revoke_before_native_invalid') === uint(start.payerNativeWei, 'basic_v2_s4_start_native_invalid')
    && uint(revokeResponse.after?.payerNativeWei, 'basic_v2_s4_revoke_after_native_invalid') === uint(end.payerNativeWei, 'basic_v2_s4_final_native_invalid')
    && uint(revokeResponse.before?.payerWethUnits, 'basic_v2_s4_revoke_before_weth_invalid') === uint(start.payerWethUnits, 'basic_v2_s4_start_weth_invalid')
    && uint(revokeResponse.after?.payerWethUnits, 'basic_v2_s4_revoke_after_weth_invalid') === uint(end.payerWethUnits, 'basic_v2_s4_final_weth_invalid')
    && taskPath.operationId === revokeAction.operationId && uint(end.usdcAllowanceUnits, 'basic_v2_s4_final_allowance_invalid') === '0'
    && uint(taskPath.finalAllowanceUnits, 'basic_v2_s4_task_final_allowance_invalid') === '0'
    && BigInt(start.payerNativeWei) - BigInt(end.payerNativeWei) === BigInt(revokeGas)
    && start.payerUsdcUnits === end.payerUsdcUnits && start.payerWethUnits === end.payerWethUnits
    && start.wethAllowanceUnits === end.wethAllowanceUnits
    && start.poolUsdcUnits === end.poolUsdcUnits && start.poolWethUnits === end.poolWethUnits
    && address(candidate.spender, 'basic_v2_s4_objective_spender_invalid') === router
    && candidate.tokenAssetId === 'USDC', 'basic_v2_s4_revoke_binding_mismatch');
  const initial = participantSnapshot(start, helpers, router);
  const final = participantSnapshot(end, helpers, router);
  return {
    initial, final,
    objective: {
      tokenAssetId: 'USDC', owner: 'participant', spender: router,
      initialAllowanceUnits: targetAmount,
      unrelatedAllowanceBaselineSha256: sha256CanonicalTaskJson({
        wethRouterAllowanceUnits: uint(start.wethAllowanceUnits, 'basic_v2_s4_weth_allowance_invalid'),
      }),
    },
    expense: null,
    extraEvidence: {
      fixtureStage: {
        classification: 'replayed_fixture_setup_outside_counted_participant_path',
        operationId: setup.operationId,
        action: setup.action,
        transactionHash: setup.transactionHash,
        gasCostWei: setup.gasCostWei,
        persistedCost: setupPersistedCost,
        initialAllowanceUnits: uint(native.initialAllowanceUnits, 'basic_v2_s4_fixture_initial_allowance_invalid'),
        positiveAllowanceUnits: targetAmount,
        beforeSetupStateSha256: sha256CanonicalTaskJson(beforeSetup),
        taskStartBlockNumber: String(start.blockNumber),
        taskStartBlockHash: hash32(start.blockHash, 'basic_v2_s4_task_start_block_invalid'),
        taskStartStateSha256: sha256CanonicalTaskJson(start),
        rawResponsePath: fixtureAction.rawResponsePath,
        rawResponseSha256: fixtureAction.rawResponseSha256,
      },
    },
  };
}

function projectionForM3(probe, helpers, manifest, identity, policy, rawResponses) {
  const capture = probe.capture;
  const reference = record(capture.referenceCapture, 'basic_v2_m3_reference_capture_missing');
  const candidate = record(reference.objectiveCandidate, 'basic_v2_m3_objective_missing');
  const snapshots = record(reference.snapshots, 'basic_v2_m3_snapshots_missing');
  const actions = record(reference.actions, 'basic_v2_m3_actions_missing');
  const approval = record(actions.approval, 'basic_v2_m3_approval_missing');
  const swap = record(actions.swap, 'basic_v2_m3_swap_missing');
  const unwrap = record(actions.unwrap, 'basic_v2_m3_unwrap_missing');
  const actionRefs = captureActions(probe, ['approve', 'swap', 'unwrap']);
  const actionRows = [approval, swap, unwrap];
  must(actionRows.every((action, index) => action.operationId === actionRefs[index].operationId
    && action.persistedCost?.payer_role === 'participant' && action.persistedCost?.receipt_status === 'success'),
  'basic_v2_m3_action_cost_binding_mismatch');
  const amount = positiveUint(candidate.exactInputUnits, 'basic_v2_m3_input_invalid');
  must(Array.isArray(rawResponses) && rawResponses.length === 3 && candidate.inputAssetId === 'USDC'
    && candidate.outputAssetId === 'ETH', 'basic_v2_m3_action_responses_missing');
  const usdc = address(manifest.contracts?.usdc?.address, 'basic_v2_m3_manifest_usdc_missing');
  const weth = address(manifest.contracts?.weth?.address, 'basic_v2_m3_manifest_weth_missing');
  const pinnedRouter = routerAddress(manifest);
  const feeTier = Number(candidate.route?.feeTier);
  const selectedActions = rawResponses.map((response) => record(response.selectedAction, 'basic_v2_m3_raw_action_missing'));
  for (const [index, action] of actionRows.entries()) {
    const response = rawResponses[index];
    const receipt = record(response.receipt, 'basic_v2_m3_raw_receipt_missing');
    const persisted = record(action.persistedCost, 'basic_v2_m3_persisted_cost_missing');
    const gasCost = uint(action.gasCostWei, 'basic_v2_m3_action_gas_invalid');
    must(response.outcome === 'success' && receipt.status === 'success'
      && hash32(receipt.transactionHash, 'basic_v2_m3_raw_tx_invalid') === hash32(action.transactionHash, 'basic_v2_m3_action_tx_invalid')
      && uint(receipt.gasCostWei, 'basic_v2_m3_raw_receipt_gas_invalid') === gasCost
      && persisted.operation_id === action.operationId && persisted.transaction_hash === action.transactionHash
      && uint(persisted.gas_cost_wei, 'basic_v2_m3_persisted_gas_invalid') === gasCost,
    'basic_v2_m3_raw_receipt_binding_mismatch');
  }
  const selectedApproval = selectedActions[0], selectedSwap = selectedActions[1], selectedUnwrap = selectedActions[2];
  must(selectedApproval.kind === 'approve' && selectedApproval.tokenAssetId === 'USDC'
    && address(selectedApproval.token, 'basic_v2_m3_approval_token_invalid') === usdc
    && address(selectedApproval.spender, 'basic_v2_m3_approval_spender_invalid') === pinnedRouter
    && uint(selectedApproval.amountUnits, 'basic_v2_m3_approval_amount_invalid') === amount
    && selectedSwap.kind === 'swap' && selectedSwap.route === 'uniswap-v3-exactInputSingle'
    && address(selectedSwap.router, 'basic_v2_m3_swap_router_invalid') === pinnedRouter
    && selectedSwap.inputAssetId === 'USDC' && selectedSwap.outputAssetId === 'WETH'
    && address(selectedSwap.tokenIn, 'basic_v2_m3_swap_token_in_invalid') === usdc
    && address(selectedSwap.tokenOut, 'basic_v2_m3_swap_token_out_invalid') === weth
    && Number(selectedSwap.fee) === feeTier
    && address(selectedSwap.poolAddress, 'basic_v2_m3_swap_pool_invalid') === address(candidate.route?.poolAddress, 'basic_v2_m3_candidate_pool_invalid')
    && String(selectedSwap.poolCodeHash).replace(/^0x/i, '').toLowerCase() === String(candidate.route?.poolCodeHash).replace(/^0x/i, '').toLowerCase()
    && uint(selectedSwap.amountInUnits, 'basic_v2_m3_raw_swap_input_invalid') === amount
    && uint(selectedSwap.amountOutMinimumUnits, 'basic_v2_m3_raw_swap_minimum_invalid')
      === uint(candidate.requiredNativeOutputMinimumWei, 'basic_v2_m3_minimum_output_invalid')
    && address(selectedSwap.recipient, 'basic_v2_m3_swap_recipient_invalid')
      === address(swap.persistedCost?.payer_address, 'basic_v2_m3_swap_payer_invalid')
    && selectedUnwrap.kind === 'unwrap', 'basic_v2_m3_selected_actions_mismatch');
  const gas = actionRows.reduce((sum, action) => sum + BigInt(uint(action.gasCostWei, 'basic_v2_m3_action_gas_invalid')), 0n);
  const gross = positiveUint(reference.measured?.grossNativeOutputWei, 'basic_v2_m3_gross_output_invalid');
  const min = positiveUint(candidate.requiredNativeOutputMinimumWei, 'basic_v2_m3_minimum_output_invalid');
  const measuredGas = uint(reference.measured?.totalGasCostWei, 'basic_v2_m3_total_gas_missing');
  const initialSnapshot = record(snapshots.before, 'basic_v2_m3_initial_state_missing');
  const finalSnapshot = record(snapshots.afterUnwrap, 'basic_v2_m3_final_state_missing');
  const initial = participantSnapshot(initialSnapshot, helpers, routerAddress(manifest));
  const final = participantSnapshot(finalSnapshot, helpers, routerAddress(manifest));
  const nativeReserveWei = positiveUint(policy.nativeReserveWei?.M3, 'basic_v2_m3_reserve_missing');
  must(reference.measured?.explicitUnwrap === true && measuredGas === gas.toString()
    && BigInt(finalSnapshot.payerNativeWei) - BigInt(initialSnapshot.payerNativeWei)
    === BigInt(gross) - gas && uint(finalSnapshot.payerUsdcUnits, 'basic_v2_m3_final_usdc_invalid')
    === (BigInt(initialSnapshot.payerUsdcUnits) - BigInt(amount)).toString()
    && uint(finalSnapshot.payerWethUnits, 'basic_v2_m3_final_weth_invalid') === uint(initialSnapshot.payerWethUnits, 'basic_v2_m3_initial_weth_invalid')
    && uint(finalSnapshot.usdcAllowanceUnits, 'basic_v2_m3_final_allowance_invalid') === '0'
    && uint(swap.amountInUnits, 'basic_v2_m3_swap_input_invalid') === amount
    && uint(approval.amountUnits, 'basic_v2_m3_approval_amount_invalid') === amount
    && uint(unwrap.amountWei, 'basic_v2_m3_unwrap_amount_invalid') === uint(swap.observedWethOutputWei, 'basic_v2_m3_swap_output_invalid')
    && uint(candidate.quoteAtPinnedSource, 'basic_v2_m3_pinned_quote_invalid') === uint(swap.observedWethOutputWei, 'basic_v2_m3_swap_output_invalid')
    && uint(selectedSwap.amountOutMinimumUnits, 'basic_v2_m3_raw_swap_minimum_invalid') === min
    && uint(selectedUnwrap.amountWei, 'basic_v2_m3_raw_unwrap_amount_invalid') === uint(swap.observedWethOutputWei, 'basic_v2_m3_swap_output_invalid')
    && BigInt(swap.observedWethOutputWei) >= min,
  'basic_v2_m3_observed_delta_mismatch');
  must(feeTier === 3000 && Number(candidate.maxSlippageBps) >= 0 && Number(candidate.maxSlippageBps) <= 10000
    && Number.isInteger(Number(candidate.maxSlippageBps)),
    'basic_v2_m3_route_objective_invalid');
  const pool = manifest.contracts?.pool3000;
  const identityPool = identity.contracts?.filter((contract) => contract.contractId === 'pool3000') ?? [];
  must(pool && identityPool.length === 1 && address(candidate.route?.poolAddress, 'basic_v2_m3_pool_address_invalid')
    === address(pool.address, 'basic_v2_m3_manifest_pool_address_invalid')
    && HASH.test(String(candidate.route?.poolCodeHash).replace(/^0x/i, ''))
    && String(candidate.route?.poolCodeHash).replace(/^0x/i, '').toLowerCase()
    === String(pool.codeHash).replace(/^0x/i, '').toLowerCase()
    && address(identityPool[0].address, 'basic_v2_m3_identity_pool_address_invalid') === address(pool.address, 'basic_v2_m3_manifest_pool_address_invalid')
    && String(identityPool[0].codeHash).replace(/^0x/i, '').toLowerCase() === String(pool.codeHash).replace(/^0x/i, '').toLowerCase()
    && policy.routeContractIds?.fee3000?.routerContractId === 'swapRouter02'
    && policy.routeContractIds?.fee3000?.poolContractId === 'pool3000', 'basic_v2_m3_route_pin_mismatch');
  must(BigInt(initialSnapshot.payerNativeWei) >= BigInt(nativeReserveWei)
    && BigInt(finalSnapshot.payerNativeWei) >= BigInt(nativeReserveWei), 'basic_v2_m3_native_reserve_not_met');
  const dexFee = ((BigInt(amount) * BigInt(feeTier) + 999999n) / 1000000n).toString();
  must(policy.expenseBudget?.dexFeeConversion === 'ceil_exact_input_units_times_fee_tier_over_1000000',
    'basic_v2_m3_dex_fee_policy_invalid');
  const expense = helpers.budget(manifest, policy, '0', gas.toString(), dexFee);
  return {
    initial, final,
    objective: {
      inputAssetId: 'USDC', exactInputUnits: amount, outputAssetId: 'ETH', minimumNativeOutputWei: min,
      permittedRoutes: [helpers.route(manifest, feeTier, 'forward')],
      maxSlippageBps: Number(candidate.maxSlippageBps),
      nativeReserveWei,
      expenseBudgetUsdcUnits: expense.budgetUsdcUnits,
    },
    expense,
  };
}

/** Build state/objective/expense fields for an actual retained basic-task v2 capture. */
export async function projectBasicV2Candidate({ probe, manifest, identity, policy, rawArtifact, helpers }) {
  record(probe, 'basic_v2_probe_missing');
  record(manifest, 'basic_v2_manifest_missing');
  record(identity, 'basic_v2_identity_missing');
  record(policy, 'basic_v2_policy_missing');
  record(helpers, 'basic_v2_helpers_missing');
  const taskId = probe.taskId;
  must(probe.status === 'captured' && ['S1', 'S2', 'S3', 'S4', 'M3'].includes(taskId)
    && probe.capture?.taskId === taskId && probe.capture?.mode === probe.mode,
  'basic_v2_probe_identity_invalid');
  must(typeof helpers.state === 'function' && typeof helpers.assetId === 'function'
    && typeof helpers.budget === 'function'
    && typeof helpers.route === 'function' && typeof helpers.readPinnedResource === 'function',
  'basic_v2_projection_helpers_missing');
  if (taskId === 'S1') {
    const actions = captureActions(probe, ['transfer']);
    const response = await readAction(rawArtifact, actions[0]);
    must(response.outcome === 'success' && probe.capture.operation?.operationId === actions[0].operationId,
      'basic_v2_s1_raw_transfer_not_successful');
    return projectionForS1(probe, helpers, manifest, policy, response);
  }
  if (taskId === 'S2') {
    const actions = captureActions(probe, ['inspect_offer']);
    const response = await readAction(rawArtifact, actions[0]);
    must(response.operationId === probe.capture.offer?.operationId
      && response.resourceId === probe.capture.objectiveCandidate?.resourceId,
    'basic_v2_s2_raw_offer_binding_mismatch');
    return projectionForS2(probe, helpers, manifest, identity, response);
  }
  if (taskId === 'S3') return projectionForS3(probe, helpers, manifest, identity, policy, rawArtifact);
  if (taskId === 'S4') return projectionForS4(probe, helpers, manifest, rawArtifact);
  if (taskId === 'M3') {
    const actions = captureActions(probe, ['approve', 'swap', 'unwrap']);
    const responses = [];
    for (const action of actions) {
      const response = await readAction(rawArtifact, action);
      must(response.outcome === 'success', 'basic_v2_m3_raw_action_not_successful');
      responses.push(response);
    }
    return projectionForM3(probe, helpers, manifest, identity, policy, responses);
  }
  throw new Error('basic_v2_task_not_supported');
}
