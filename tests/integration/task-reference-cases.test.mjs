import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const referenceApi = await import(new URL('../../packages/benchmark-environment/dist/probe/task-reference-cases.js', import.meta.url));
const {
  BTS_TASK_ORDER,
  buildTaskReferenceCaseIndex,
  canonicalSha256,
  projectDeliveryEnvelope,
  projectM1PaymentRequirements,
  projectS2OfferObjective,
} = referenceApi;
const driverApi = await import(new URL('../../packages/benchmark-environment/dist/probe/task-reference-case-drivers.js', import.meta.url));
const { parseAbiUint256Word } = driverApi;
const manifest = JSON.parse(await readFile(new URL('../../infrastructure/benchmark-environment/manifest.json', import.meta.url), 'utf8'));

const sha = (value) => createHash('sha256').update(value).digest('hex');
const artifact = (path) => ({ path, sha256: sha(path), boundary: 'actual-tool-http' });

function transferCapture() {
  return {
    schemaVersion: 'bts-transfer-probe/v1',
    classification: 'selected_executor_primitive_capture_not_bts_acceptance',
    status: 'captured',
    operation: { transactionHash: `0x${'1'.repeat(64)}`, receiptStatus: 'success' },
    receipt: { blockHash: `0x${'2'.repeat(64)}`, status: '0x1' },
    before: { blockNumber: '100' },
    after: { blockNumber: '101' },
  };
}

function catalogCapture() {
  return {
    schemaVersion: 'bts-resource-catalog-probe/v1',
    classification: 'selected_executor_resource_catalog_capture_not_bts_acceptance',
    status: 'captured',
    purchases: [{
      resourceId: 'bef-resource-v1',
      resourceSha256: sha('content'),
      paymentTransactionHash: `0x${'3'.repeat(64)}`,
      receiptStatus: '0x1',
      paymentAndDeliveryPersisted: true,
    }],
  };
}

function reverseSwapCapture() {
  return {
    schemaVersion: 'bts-reverse-swap-probe/v1',
    classification: 'selected_executor_reverse_swap_capture_not_bts_acceptance',
    status: 'captured',
    swap: {
      transactionHash: `0x${'4'.repeat(64)}`,
      status: 'success',
      inputAssetId: 'USDC',
      outputAssetId: 'WETH',
    },
    snapshots: { beforeApproval: {}, afterApproval: {}, afterSwap: {} },
  };
}

function s2Capture({ afterBlockNumber = '100', afterBlockHash = `0x${'a'.repeat(64)}` } = {}) {
  const blockHash = `0x${'a'.repeat(64)}`;
  const state = {
    blockNumber: '100', blockHash,
    payerNativeEthWei: '1', payerUsdcUnits: '2', payerWethUnits: '0',
    usdcRouterAllowanceUnits: '0', wethRouterAllowanceUnits: '0',
  };
  const zeroCounts = {
    nonOfferOperations: '0', purchases: '0', payments: '0', deliveries: '0', denials: '0',
    x402Observations: '0', selectedExecutions: '0', selectedExecutionEvents: '0', transactionCosts: '0',
  };
  return {
    schemaVersion: 'bts-s2-offer-reference/v1',
    classification: 'actual_tool_http_offer_read_no_economic_effects_not_bts_acceptance',
    status: 'captured',
    offer: { operationId: 'read-op' },
    objectiveCandidate: { referenceAnswer: { amountUnits: '1' } },
    noEffectInterval: {
      blockBefore: { number: '100', hash: blockHash },
      blockAfterGet: { number: afterBlockNumber, hash: afterBlockHash },
      blockAtEnd: { number: afterBlockNumber, hash: afterBlockHash },
      stateBefore: state,
      stateAfter: state,
      databaseBefore: { operations: 0, payments: 0, deliveries: 0 },
      databaseAfter: { operations: 1, payments: 0, deliveries: 0 },
      effectCountsBefore: zeroCounts,
      effectCountsAfter: zeroCounts,
      offerReadOperation: { operationId: 'read-op', operationKind: 'offer', status: 'accepted', receiptStatus: 'not_submitted' },
    },
  };
}

function m1Capture() {
  const transactionHash = `0x${'5'.repeat(64)}`;
  const expectedContentHash = sha('pinned-content');
  return {
    schemaVersion: 'bts-m1-single-purchase-reference/v1',
    classification: 'actual_tool_http_single_purchase_delivery_not_bts_task_acceptance',
    status: 'captured',
    operation: { status: 'delivered', transactionHash },
    payment: { status: 'success', transactionHash },
    delivery: { contentHash: expectedContentHash },
    expectedContentHash,
    component: { componentId: 'delivery-bef-market-state-brief-v1' },
    paymentRequirements: { amountUnits: '125000' },
    purchaseCountFacts: { purchaseCount: '1', paymentCount: '1', deliveryCount: '1' },
    objectiveCandidate: { operatingBudgetUsdcUnits: null },
  };
}

test('delivery envelope projection pins actual bytes, schema fields, hash predicate, and provenance', () => {
  const content = { resourceId: 'bef-resource-v1', value: 'pinned fixture' };
  const rawBytes = Buffer.from(JSON.stringify(content));
  const contentHash = sha(rawBytes);
  const result = projectDeliveryEnvelope({
    envelope: {
      operationId: 'opaque-operation-id',
      resourceId: 'bef-resource-v1',
      contentType: 'application/json',
      contentHash,
      contentBytes: rawBytes.toString('base64'),
      content,
    },
    expectedResourceId: 'bef-resource-v1',
    expectedContentHash: contentHash,
    provenanceId: 'synthetic-benchmark-fixture',
  });

  assert.deepEqual(result.projection, {
    resourceId: 'bef-resource-v1',
    contentType: 'application/json',
    contentHash,
    contentBytes: rawBytes.toString('base64'),
  });
  assert.equal(result.contentBytesSha256, contentHash);
  assert.deepEqual(result.parsedContent, content);
  assert.deepEqual(result.component.validator.requiredFields, [
    { name: 'resourceId', type: 'string' },
    { name: 'contentType', type: 'string' },
    { name: 'contentHash', type: 'sha256' },
    { name: 'contentBytes', type: 'string' },
  ]);
  assert.deepEqual(result.component.validator.predicates, [
    { op: 'equals', field: 'resourceId', value: 'bef-resource-v1' },
    { op: 'equals', field: 'contentType', value: 'application/json' },
    { op: 'equals', field: 'contentHash', value: contentHash },
  ]);
  assert.deepEqual(result.component.sourceIds, ['synthetic-benchmark-fixture']);
});

test('delivery envelope projection rejects mismatched bytes, manifest digest, and payload content', () => {
  const bytes = Buffer.from('{"pinned":true}');
  const contentHash = sha(bytes);
  const envelope = {
    resourceId: 'bef-resource-v1', contentType: 'application/json', contentHash,
    contentBytes: bytes.toString('base64'), content: { pinned: true },
  };
  const project = (changes = {}, expectedContentHash = contentHash) => projectDeliveryEnvelope({
    envelope: { ...envelope, ...changes },
    expectedResourceId: 'bef-resource-v1',
    expectedContentHash,
    provenanceId: 'synthetic-benchmark-fixture',
  });

  assert.throws(() => project({}, sha('different pinned bytes')), /fields_mismatch/);
  assert.throws(() => project({ contentBytes: Buffer.from('{"pinned":false}').toString('base64') }), /hash_mismatch/);
  assert.throws(() => project({ content: { pinned: false } }), /content_mismatch/);
  assert.throws(() => project({ contentType: 'text/plain' }), /fields_mismatch/);
});

test('task reference index preserves the fixed twelve-task order and never implies release readiness', () => {
  const index = buildTaskReferenceCaseIndex({
    captures: [
      { captureId: 's1-transfer', capture: transferCapture(), artifacts: [artifact('http/s1.json')] },
      { captureId: 'resource-catalog', capture: catalogCapture(), artifacts: [artifact('http/catalog.json')] },
      { captureId: 'reverse-swap', capture: reverseSwapCapture(), artifacts: [artifact('http/swap.json')] },
    ],
  });

  assert.deepEqual(index.taskOrder, BTS_TASK_ORDER);
  assert.deepEqual(index.cases.map(({ taskId }) => taskId), BTS_TASK_ORDER);
  assert.equal(index.releaseReadiness, 'blocked');
  assert.ok(index.cases.every((taskCase) => taskCase.releaseReadiness === 'blocked'));
  assert.deepEqual(index.observedCaptureIds, ['s1-transfer', 'resource-catalog', 'reverse-swap']);
  assert.equal(index.cases.find(({ taskId }) => taskId === 'S1').evidenceStatus, 'observed');
  assert.equal(index.cases.find(({ taskId }) => taskId === 'S2').evidenceStatus, 'not_observed');
  assert.ok(index.cases.find(({ taskId }) => taskId === 'S2').blockers.includes('answer_reference_not_bound_to_an_admitted_task_result'));
  assert.ok(index.cases.find(({ taskId }) => taskId === 'M3').blockers.includes('observed_swap_output_is_weth_not_native_eth'));
  assert.ok(index.cases.find(({ taskId }) => taskId === 'S4').blockers.includes('allowance_revocation_without_principal_movement_not_captured'));
});

test('only capture-shaped primitive results are indexed, and component validators do not unblock whole cases', () => {
  const projectedComponent = projectDeliveryEnvelope({
    envelope: {
      resourceId: 'bef-resource-v1', contentType: 'application/json', contentHash: sha('"raw"'),
      contentBytes: Buffer.from('"raw"').toString('base64'), content: 'raw',
    },
    expectedResourceId: 'bef-resource-v1', expectedContentHash: sha('"raw"'),
    provenanceId: 'synthetic-benchmark-fixture',
  }).component;
  const index = buildTaskReferenceCaseIndex({
    captures: [
      { captureId: 's1-transfer', capture: { ...transferCapture(), classification: 'caller-supplied-score' }, artifacts: [artifact('http/fake.json')] },
      { captureId: 'resource-catalog', capture: catalogCapture(), artifacts: [artifact('http/catalog.json')] },
    ],
    dataComponents: [projectedComponent],
  });

  assert.equal(index.captures.find(({ captureId }) => captureId === 's1-transfer').status, 'unavailable');
  assert.equal(index.cases.find(({ taskId }) => taskId === 'S1').evidenceStatus, 'not_observed');
  const m1 = index.cases.find(({ taskId }) => taskId === 'M1');
  const h1 = index.cases.find(({ taskId }) => taskId === 'H1');
  assert.equal(m1.dataComponents.length, 0);
  assert.equal(h1.dataComponents.length, 1);
  assert.equal(m1.releaseReadiness, 'blocked');
  assert.equal(m1.evidenceStatus, 'not_observed');
  assert.ok(m1.blockers.includes('operating_expense_budget_not_pinned'));
  assert.ok(h1.blockers.includes('finite_required_component_set_and_operating_budget_not_pinned'));
});

test('S2 reference shape requires one stable block across the offer interval and remains blocked', () => {
  const index = buildTaskReferenceCaseIndex({
    captures: [{ captureId: 's2-readonly-offer', capture: s2Capture(), artifacts: [artifact('http/s2-offer.json')] }],
  });
  const s2 = index.cases.find(({ taskId }) => taskId === 'S2');
  assert.equal(s2.evidenceStatus, 'observed');
  assert.equal(s2.releaseReadiness, 'blocked');
  assert.ok(s2.blockers.includes('answer_reference_not_bound_to_an_admitted_task_result'));

  const changedBlockIndex = buildTaskReferenceCaseIndex({
    captures: [{
      captureId: 's2-readonly-offer', capture: s2Capture({ afterBlockNumber: '101', afterBlockHash: `0x${'b'.repeat(64)}` }),
      artifacts: [artifact('http/s2-offer-changed-block.json')],
    }],
  });
  assert.equal(changedBlockIndex.captures[0].status, 'unavailable');
  assert.equal(changedBlockIndex.cases.find(({ taskId }) => taskId === 'S2').evidenceStatus, 'not_observed');
});

test('M1 one-purchase facts bind a delivery component but cannot unblock the case without a pinned budget', () => {
  const index = buildTaskReferenceCaseIndex({
    captures: [{ captureId: 'm1-single-purchase', capture: m1Capture(), artifacts: [artifact('http/m1-purchase.json')] }],
  });
  const m1 = index.cases.find(({ taskId }) => taskId === 'M1');
  assert.equal(m1.evidenceStatus, 'observed');
  assert.equal(m1.dataComponents.length, 1);
  assert.equal(m1.objectiveCandidate.operatingBudgetUsdcUnits, null);
  assert.equal(m1.releaseReadiness, 'blocked');
  assert.ok(m1.blockers.includes('operating_expense_budget_not_pinned'));
});

test('ABI uint256 decoding accepts padded zero/nonzero words and rejects malformed words', () => {
  assert.equal(parseAbiUint256Word(`0x${'0'.repeat(64)}`), '0');
  assert.equal(parseAbiUint256Word(`0x${'0'.repeat(63)}1`), '1');
  assert.equal(parseAbiUint256Word(`0x${'0'.repeat(62)}ff`), '255');
  assert.throws(() => parseAbiUint256Word('0x1'), /abi_uint256_word_invalid/);
  assert.throws(() => parseAbiUint256Word(`0x${'g'.repeat(64)}`), /abi_uint256_word_invalid/);
});

test('S2 and M1 objective projections derive actual tuples from pinned manifest values', () => {
  const pinnedResource = manifest.x402.catalog.find((entry) => entry.resourceId === manifest.x402.resourceId);
  assert.ok(pinnedResource);
  const payTo = `0x${'1'.repeat(40)}`;
  const payment = {
    scheme: manifest.x402.scheme,
    network: manifest.x402.network,
    asset: manifest.x402.asset,
    amount: pinnedResource.offers[0].amount,
    payTo,
    transferMethod: manifest.x402.assetTransferMethod,
  };
  const offerResponse = {
    resourceId: pinnedResource.resourceId,
    resourceSha256: pinnedResource.resourceSha256,
    contentType: pinnedResource.contentType,
    schema: pinnedResource.schema,
    provenance: pinnedResource.provenance,
    payment,
    offers: pinnedResource.offers.map((offer) => ({ id: offer.id, payment: { ...payment, amount: offer.amount } })),
    freeInspection: true,
    deliveryState: 'not_delivered',
  };
  const s2 = projectS2OfferObjective({ response: offerResponse, pinnedResource, paymentPolicy: manifest.x402 });
  assert.equal(s2.resourceId, pinnedResource.resourceId);
  assert.equal(s2.completePaymentRequirements.amountUnits, pinnedResource.offers[0].amount);
  assert.ok(s2.requiredAnswerFields.includes('assetTransferMethod'));
  assert.ok(s2.referenceAnswer.authFields.length > 0);

  const m1Resource = manifest.x402.catalog.find((entry) => entry.resourceId === 'bef-market-state-brief-v1');
  assert.ok(m1Resource);
  const m1Offer = m1Resource.offers[0];
  const requirements = {
    scheme: manifest.x402.scheme,
    network: manifest.x402.network,
    asset: manifest.x402.asset,
    amount: m1Offer.amount,
    payTo,
    extra: {
      assetTransferMethod: manifest.x402.assetTransferMethod,
      paymentFlow: 'authorization',
      name: manifest.x402.eip712Domain.name,
      version: manifest.x402.eip712Domain.version,
    },
  };
  const m1 = projectM1PaymentRequirements({
    resourceId: m1Resource.resourceId, offerId: m1Offer.id, amountUnits: m1Offer.amount,
    requirements, paymentPolicy: manifest.x402,
  });
  assert.equal(m1.amountUnits, m1Offer.amount);
  assert.equal(m1.resourceId, m1Resource.resourceId);
  assert.equal(m1.recipient, payTo.toLowerCase());
});

test('primitive status stays unavailable without hashed actual-tool evidence', () => {
  const index = buildTaskReferenceCaseIndex({
    captures: [{ captureId: 's1-transfer', capture: transferCapture(), artifacts: [] }],
  });
  assert.equal(index.captures[0].status, 'unavailable');
  assert.equal(index.cases.find(({ taskId }) => taskId === 'S1').evidenceStatus, 'not_observed');
});

test('canonical reference hashes ignore object insertion order', () => {
  assert.equal(canonicalSha256({ a: 1, b: { c: 2, d: 3 } }), canonicalSha256({ b: { d: 3, c: 2 }, a: 1 }));
});
