import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const objectiveApi = await import(new URL('../../packages/benchmark-environment/dist/probe/task-reference-catalog-objectives.js', import.meta.url));
const envelopeApi = await import(new URL('../../packages/benchmark-environment/dist/probe/task-reference-cases.js', import.meta.url));
const {
  minimumM2Offer,
  projectM2CatalogObjective,
  projectPinnedPublicCatalog,
  projectS3CatalogObjective,
} = objectiveApi;
const { buildTaskReferenceCaseIndex, projectDeliveryEnvelope } = envelopeApi;
const manifest = JSON.parse(await readFile(new URL('../../infrastructure/benchmark-environment/manifest.json', import.meta.url), 'utf8'));

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const payTo = '0x572a3a8c2cbBC29d34e2026624f7B73cf61936fE';
const payer = '0x970785B2639797D6671C9dB5b4A0Cd1F3b8f734d';

function publicCatalog(overrides = {}) {
  const catalog = manifest.x402.catalog.map((resource) => ({
    resourceId: resource.resourceId,
    resourceSha256: resource.resourceSha256,
    contentType: resource.contentType,
    dataType: resource.dataType,
    schema: resource.schema,
    provenance: resource.provenance,
    offers: resource.offers.map((offer) => ({
      id: offer.id,
      payment: {
        scheme: manifest.x402.scheme,
        network: manifest.x402.network,
        asset: manifest.x402.asset,
        amount: offer.amount,
        payTo,
        transferMethod: manifest.x402.assetTransferMethod,
      },
    })),
  }));
  return {
    freeInspection: true,
    deliveryState: 'not_delivered',
    catalog: catalog.map((resource) => ({ ...resource, ...(overrides[resource.resourceId] ?? {}) })),
  };
}

async function componentFor(resourceId) {
  const resource = manifest.x402.catalog.find((item) => item.resourceId === resourceId);
  const contentBytes = await readFile(new URL(`../../${resource.resourcePath}`, import.meta.url));
  const digest = sha(contentBytes);
  return projectDeliveryEnvelope({
    envelope: {
      resourceId,
      contentType: resource.contentType,
      contentHash: digest,
      contentBytes: contentBytes.toString('base64'),
      content: JSON.parse(contentBytes.toString('utf8')),
    },
    expectedResourceId: resourceId,
    expectedContentHash: digest,
    provenanceId: resource.provenance.classification,
  }).component;
}

function observedCatalog() {
  return projectPinnedPublicCatalog({ response: publicCatalog(), manifest });
}

async function components() {
  return Promise.all(manifest.x402.catalog.map((resource) => componentFor(resource.resourceId)));
}

test('public catalog projection binds every advertised field to the immutable manifest', () => {
  const projection = observedCatalog();
  assert.equal(projection.resources.length, manifest.x402.catalog.length);
  assert.equal(projection.facilitatorAddress, payTo.toLowerCase());
  assert.equal(projection.offers.length, manifest.x402.catalog.reduce((total, resource) => total + resource.offers.length, 0));
  assert.ok(projection.offers.every((offer) => offer.dataType.length > 0));
  assert.ok(projection.offers.every((offer) => offer.paymentRequirements.amountUnits === offer.advertisedTotalPriceUsdcUnits));
  assert.ok(projection.offers.every((offer) => offer.paymentRequirements.recipient === payTo.toLowerCase()));
  assert.ok(projection.offers.every((offer) => !Object.hasOwn(offer, 'deliveryValidator')),
    'catalog metadata alone does not fabricate a delivery validator');
});

test('catalog projection rejects missing or contradictory public dataType, price, payee, and resource hash', () => {
  const response = publicCatalog();
  const clone = () => structuredClone(response);

  const noType = clone();
  delete noType.catalog[0].dataType;
  assert.throws(() => projectPinnedPublicCatalog({ response: noType, manifest }), /manifest_binding_mismatch/);

  const wrongType = clone();
  wrongType.catalog[0].dataType = 'made-up-type';
  assert.throws(() => projectPinnedPublicCatalog({ response: wrongType, manifest }), /manifest_binding_mismatch/);

  const wrongPrice = clone();
  wrongPrice.catalog[0].offers[0].payment.amount = '99999';
  assert.throws(() => projectPinnedPublicCatalog({ response: wrongPrice, manifest }), /offer_binding_mismatch/);

  const wrongPayee = clone();
  wrongPayee.catalog[0].offers[0].payment.payTo = `0x${'1'.repeat(40)}`;
  assert.throws(() => projectPinnedPublicCatalog({ response: wrongPayee, manifest }), /facilitator_changed/);

  const wrongHash = clone();
  wrongHash.catalog[0].resourceSha256 = '0'.repeat(64);
  assert.throws(() => projectPinnedPublicCatalog({ response: wrongHash, manifest }), /manifest_binding_mismatch/);
});

test('S3 catalog candidate permits an observed qualifying extended offer without imposing cheapest choice', async () => {
  const candidate = projectS3CatalogObjective({
    publicCatalog: observedCatalog(),
    components: await components(),
    requiredDataType: 'market-state-brief',
    referenceOfferId: 'market-brief-extended',
  });

  assert.equal(candidate.taskId, 'S3');
  assert.equal(candidate.required.requiredDataType, 'market-state-brief');
  assert.equal(candidate.required.maxAdvertisedTotalPriceUsdcUnits, '250000');
  assert.equal(candidate.referenceAnswerCandidate.offerId, 'market-brief-extended');
  assert.equal(candidate.minAdvertisedTotalPriceUsdcUnits, '125000');
  assert.deepEqual(candidate.eligibleOfferIds, ['market-brief-standard', 'market-brief-extended']);
  assert.equal(candidate.catalog.length, 4);
  assert.ok(candidate.catalog.every((offer) => offer.paymentRequirements.resourceId === offer.resourceId));
  assert.ok(candidate.catalog.every((offer) => offer.deliveryValidator.payloadSchemaVersion === 'bef-delivery-envelope/v1'));
  assert.equal(candidate.classification, 'derived_from_pinned_public_catalog_not_release_or_answer');
  assert.equal(Object.hasOwn(candidate, 'releaseReadiness'), false);
});

test('M2 catalog candidate selects exactly one lowest advertised qualifying offer and leaves budget unresolved', async () => {
  const catalog = observedCatalog();
  const objective = projectM2CatalogObjective({
    publicCatalog: catalog,
    components: [await componentFor('bef-market-state-brief-v1')],
  });
  const minimum = minimumM2Offer(objective);

  assert.equal(objective.required.requiredDataType, 'market-state-brief');
  assert.equal(objective.required.maxAdvertisedTotalPriceUsdcUnits, '250000');
  assert.equal(objective.catalog.length, 2);
  assert.deepEqual(objective.eligibleOfferIds, ['market-brief-standard', 'market-brief-extended']);
  assert.equal(objective.minAdvertisedTotalPriceUsdcUnits, '125000');
  assert.equal(minimum.offerId, 'market-brief-standard');
  assert.equal(minimum.advertisedTotalPriceUsdcUnits, '125000');
  assert.ok(objective.catalog.every((offer) => offer.deliveryValidator.predicates.some((predicate) => predicate.field === 'contentHash')));
  assert.equal(Object.hasOwn(objective, 'expenseBudgetUsdcUnits'), false,
    'the catalog projection cannot invent an expense budget from one successful purchase');
});

test('M2 projection rejects missing delivery evidence, indistinct prices, and a nonminimum reference offer', async () => {
  const catalog = observedCatalog();
  await assert.rejects(async () => projectM2CatalogObjective({ publicCatalog: catalog, components: [] }), /delivery_validator_unobserved/);

  const equalPrices = structuredClone(catalog);
  const briefExtended = equalPrices.offers.find((item) => item.offerId === 'market-brief-extended');
  briefExtended.advertisedTotalPriceUsdcUnits = '125000';
  assert.throws(() => projectM2CatalogObjective({
    publicCatalog: equalPrices,
    components: [],
  }), /prices_not_distinct/);

  const wrongReference = projectM2CatalogObjective({
    publicCatalog: catalog,
    components: [await componentFor('bef-market-state-brief-v1')],
  });
  wrongReference.referenceAnswerCandidate.offerId = 'market-brief-extended';
  assert.throws(() => minimumM2Offer(wrongReference), /reference_answer_not_minimum/);
});

test('reference index accepts a fixed-block S3 catalog read but leaves answer-to-cutoff binding blocked', async () => {
  const candidate = projectS3CatalogObjective({
    publicCatalog: observedCatalog(),
    components: await components(),
    requiredDataType: 'market-state-brief',
    referenceOfferId: 'market-brief-extended',
  });
  const state = {
    blockNumber: '100', blockHash: `0x${'a'.repeat(64)}`, payerNativeEthWei: '10', payerUsdcUnits: '20',
    payerWethUnits: '30', usdcRouterAllowanceUnits: '0', wethRouterAllowanceUnits: '0',
  };
  const zeroCounts = {
    operations: '0', payments: '0', deliveries: '0', denials: '0', x402Observations: '0',
    selectedExecutions: '0', selectedExecutionEvents: '0', transactionCosts: '0', participantCosts: '0',
  };
  const capture = {
    schemaVersion: 'bts-s3-catalog-reference/v1',
    classification: 'actual_tool_http_public_catalog_read_and_derived_answer_candidate_not_bts_acceptance',
    status: 'captured',
    catalogResponse: publicCatalog(),
    objectiveCandidate: { ...candidate, policyReviewStatus: 'candidate_requires_release_review' },
    noEffectInterval: {
      blockBefore: { number: '100', hash: state.blockHash },
      blockAfterGet: { number: '100', hash: state.blockHash },
      blockAtEnd: { number: '100', hash: state.blockHash },
      stateBefore: state, stateAfter: state,
      databaseBefore: { operations: 0, payments: 0, deliveries: 0 },
      databaseAfter: { operations: 0, payments: 0, deliveries: 0 },
      effectCountsBefore: zeroCounts, effectCountsAfter: zeroCounts,
    },
  };
  const artifact = { path: 'http/s3-catalog.json', sha256: sha('s3'), boundary: 'actual-tool-http' };
  const index = buildTaskReferenceCaseIndex({ captures: [{ captureId: 's3-readonly-catalog', capture, artifacts: [artifact] }] });
  const s3 = index.cases.find((item) => item.taskId === 'S3');
  assert.equal(s3.evidenceStatus, 'observed');
  assert.equal(s3.releaseReadiness, 'blocked');
  assert.equal(s3.objectiveCandidate.referenceAnswerCandidate.offerId, 'market-brief-extended');
  assert.ok(s3.blockers.includes('answer_reference_not_bound_to_an_admitted_task_result'));

  const contradictory = structuredClone(capture);
  contradictory.noEffectInterval.effectCountsAfter.payments = '1';
  const rejected = buildTaskReferenceCaseIndex({ captures: [{ captureId: 's3-readonly-catalog', capture: contradictory, artifacts: [artifact] }] });
  assert.equal(rejected.cases.find((item) => item.taskId === 'S3').evidenceStatus, 'not_observed');
});

test('reference index requires a correlated single M2 minimum payment, delivery, receipt, and facilitator cost', async () => {
  const observedComponent = await componentFor('bef-market-state-brief-v1');
  const objective = projectM2CatalogObjective({
    publicCatalog: observedCatalog(),
    components: [observedComponent],
  });
  const transactionHash = `0x${'5'.repeat(64)}`;
  const payment = {
    status: 'settled', operationId: 'operation-1', transactionHash, receiptStatus: '0x1',
    payerAddress: payer.toLowerCase(), recipient: payTo.toLowerCase(), assetId: manifest.x402.asset.toLowerCase(),
    network: manifest.x402.network, amountUnits: '125000',
  };
  const contentHash = observedComponent.validator.predicates.find((predicate) => predicate.field === 'contentHash').value;
  const capture = {
    schemaVersion: 'bts-m2-minimum-purchase-reference/v1',
    classification: 'actual_tool_http_minimum_qualifying_purchase_and_verified_delivery_not_bts_acceptance',
    status: 'captured',
    objectiveCandidate: {
      ...objective, expenseBudgetUsdcUnits: null, tiePolicy: 'all_minimum_advertised_total_prices_qualify',
      duplicatePurchaseIdentity: 'one_public_purchase_operation', policyReviewStatus: 'candidate_requires_budget_and_release_review',
    },
    selectedOffer: { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', advertisedTotalPriceUsdcUnits: '125000', operationId: 'operation-1', transactionHash },
    operation: { operationId: 'operation-1', operationKind: 'purchase', status: 'delivered', receiptStatus: 'success', transactionHash },
    receipt: { transactionHash, status: '0x1', blockNumber: '101', blockHash: `0x${'6'.repeat(64)}`, from: payTo.toLowerCase() },
    transferEffect: { tokenAssetId: manifest.x402.asset.toLowerCase(), from: payer.toLowerCase(), to: payTo.toLowerCase(), amountUnits: '125000', receiptTransferCountFromPayer: 1 },
    payment,
    delivery: { resourceId: 'bef-market-state-brief-v1', contentHash, component: observedComponent, contentBytes: 818 },
    expenseObservations: {
      participantGasCostCount: '0', transactionGasPayer: 'facilitator', operatingBudgetUsdcUnits: null,
      facilitatorGasCost: { transactionHash, payerRole: 'facilitator', modeledGasFeeUsdcUnits: '1322' },
    },
    purchaseCounts: { purchaseOperations: 1, payments: 1, deliveries: 1, transactionCosts: 1 },
  };
  const artifact = { path: 'http/m2-paid.json', sha256: sha('m2'), boundary: 'actual-tool-http' };
  const index = buildTaskReferenceCaseIndex({ captures: [{ captureId: 'm2-minimum-purchase', capture, artifacts: [artifact] }] });
  const m2 = index.cases.find((item) => item.taskId === 'M2');
  assert.equal(m2.evidenceStatus, 'observed');
  assert.equal(m2.releaseReadiness, 'blocked');
  assert.equal(m2.objectiveCandidate.expenseBudgetUsdcUnits, null);
  assert.ok(m2.blockers.includes('operating_expense_budget_not_pinned'));

  const contradictory = structuredClone(capture);
  contradictory.transferEffect.amountUnits = '250000';
  const rejected = buildTaskReferenceCaseIndex({ captures: [{ captureId: 'm2-minimum-purchase', capture: contradictory, artifacts: [artifact] }] });
  assert.equal(rejected.cases.find((item) => item.taskId === 'M2').evidenceStatus, 'not_observed');
});
