import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalTaskJson } from './task-release.js';
import { evaluateTaskRubric, type PersistedTaskObservations, type TaskEvidenceBinding, type TrustedTaskRun } from './task-evaluator.js';
import { validM1CapturePacket, validM1PaymentPacket } from './task-m1-capture-packet.fixture.js';
import { M1CapturePacketError, parseM1CapturePacket, projectM1PacketObservations, validateM1CapturePacket, splitPayRequestSha256,
  type M1CapturePacket, type M1PacketProjectionContext } from './task-m1-capture-packet.js';
import type { EvidenceReference, TaskCase } from './task-release.js';

const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

test('split payment request identity preserves the exact canonical body used on the wire', () => {
  const body={resourceId:'r',offerId:'o',readHandle:{kind:'offer',operationId:'p'},acceptedTerms:{payTo:'recipient',amount:'1'}};
  const wire='{"method":"POST","path":"/tools/bef-env-a/pay","body":{"acceptedTerms":{"amount":"1","payTo":"recipient"},"offerId":"o","readHandle":{"kind":"offer","operationId":"p"},"resourceId":"r"}}';
  assert.equal(splitPayRequestSha256('bef-env-a',body),digest(Buffer.from(wire)));
  assert.notEqual(splitPayRequestSha256('bef-env-a',body),digest(Buffer.from(JSON.stringify({method:'POST',path:'/tools/bef-env-a/pay',body}))));
});

test('synthetic packet validates and parses without changing its canonical bytes', () => {
  const packet = validM1CapturePacket();
  const bytes = Buffer.from(canonicalTaskJson(packet));
  assert.deepEqual(validateM1CapturePacket(packet), packet);
  assert.deepEqual(parseM1CapturePacket(bytes), packet);
});

test('actual pinned public environment manifest bytes hash-bind and derive the first resource pin', () => {
  const manifestBytes = readFileSync(new URL('../../../infrastructure/benchmark-environment/manifest.json', import.meta.url));
  const expectedSha256 = digest(manifestBytes);
  const packet = validateM1CapturePacket(validM1CapturePacket(manifestBytes));
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as {
    x402: { catalog: Array<{ resourceId: string; resourceSha256: string; contentType: string; offers: Array<{ id: string; amount: string }> }> };
  };
  const resource = manifest.x402.catalog[0]!;
  assert.equal(packet.bef.environmentManifest.sha256, expectedSha256);
  assert.equal(packet.execution.environmentManifestHash, expectedSha256);
  assert.equal(packet.bef.resourcePin.resourceId, resource.resourceId);
  assert.equal(packet.bef.resourcePin.resourceSha256, resource.resourceSha256);
  assert.equal(packet.bef.resourcePin.contentType, resource.contentType);
  assert.deepEqual(packet.bef.resourcePin.offers, resource.offers);
});

test('catalog inspection permits the real public metadata and a read without a BEF operation identity', () => {
  const packet = validM1CapturePacket();
  const resource = packet.bef.resourcePin;
  packet.closure.actionCutoffSequence = 1;
  packet.closure.reconciledActionSequence = 1;
  packet.ownerActions = [{ actionId: '10000000-0000-4000-8000-000000000061', actionSequence: 1,
    ownerOperationId: 'synthetic-owner-operation-catalog', actionKind: 'inspect_catalog', commandSha256: '6'.repeat(64),
    receiptStatus: 'observed', actionEvidence: { path: 'artifacts/runs/owner-identity-bef-task-coordinator/action/catalog-synthetic.json',
      sha256: '7'.repeat(64), boundary: 'actual_tool_http_x402_local_evm_application_store' }, befOperationId: null, transactionHash: null,
    rawResponseSha256: '8'.repeat(64), paymentProtocol: null, participantToolResponse: { freeInspection: true, deliveryState: 'not_delivered',
      catalog: [{ resourceId: resource.resourceId, resourceSha256: resource.resourceSha256, contentType: resource.contentType, dataType: 'risk-policy',
        schema: 'm1-resource/v1', provenance: { classification: 'synthetic-benchmark-fixture', boundary: 'private acceptance environment', source: 'repository fixture' },
        offers: resource.offers.map((offer) => ({ id: offer.id, payment: { scheme: 'exact', network: 'eip155:8453', asset: resource.paymentPolicy.asset,
          amount: offer.amount, payTo: `0x${'0'.repeat(38)}c3`, transferMethod: 'eip3009' } })) }] } }];
  assert.equal(validateM1CapturePacket(packet).ownerActions[0]?.befOperationId, null);
});

test('packet rejects signed authorization/header material and raw transaction calldata', () => {
  const header = validM1CapturePacket() as unknown as Record<string, unknown>;
  header.rpc = { ...(header.rpc as Record<string, unknown>), 'x-payment': 'not retained' };
  assert.throws(() => validateM1CapturePacket(header), (error: unknown) => error instanceof M1CapturePacketError &&
    error.code === 'M1_CAPTURE_PACKET_SECRET_FIELD');

  const calldata = validM1CapturePacket() as unknown as Record<string, unknown>;
  const rpc = calldata.rpc as Record<string, unknown>;
  rpc.paymentProofs = [{ operationId: '10000000-0000-4000-8000-000000000012', paymentId: '10000000-0000-4000-8000-000000000013',
    transactionHash: `0x${'1'.repeat(64)}`, transaction: { hash: `0x${'1'.repeat(64)}`, from: `0x${'2'.repeat(40)}`, to: null,
      value: '0', nonce: '1', blockNumber: '1', blockHash: `0x${'3'.repeat(64)}`, input: `0x${'4'.repeat(64)}` },
    receipt: {} }];
  assert.throws(() => validateM1CapturePacket(calldata), (error: unknown) => error instanceof M1CapturePacketError &&
    error.code === 'M1_CAPTURE_PACKET_INVALID');
});

const TEST_CAPTURE: EvidenceReference = {
  path: 'artifacts/runs/owner-identity-bef-task-coordinator/observation/10000000-0000-4000-8000-000000000003/M1/capture.json',
  sha256: 'f'.repeat(64), boundary: 'actual_tool_http_x402_local_evm_application_store',
};

function m1Context(packet: M1CapturePacket, alternateExpected = false): M1PacketProjectionContext {
  const binding = packet.binding as unknown as TaskEvidenceBinding;
  const recipient = `0x${'0'.repeat(38)}c3`;
  const resourceId = packet.bef.resourcePin.resourceId;
  const asset = packet.bef.resourcePin.paymentPolicy.asset;
  const taskCase = {
    caseId: binding.caseId, caseHash: binding.caseHash, mode: 'training', rubricVersion: 'bts-rubric/v1', rubricHash: binding.rubricHash,
    taskWeight: 2, mandatoryRules: ['permitted_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
    executionIdentityHash: '1'.repeat(64), taskDeadlineSeconds: 300,
    initialState: { stateSha256: '2'.repeat(64), balances: [
      { account: 'participant', assetId: 'USDC', amountUnits: '500000' },
      { account: 'participant', assetId: 'ETH', amountUnits: '1000000000000000000' },
    ], allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [] },
    initialStateEvidence: { ...TEST_CAPTURE, path: 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/m1-case.json' },
    referencePath: { evidence: { ...TEST_CAPTURE, path: 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/m1-reference.json' },
      actionCount: 3, initialStateSha256: '2'.repeat(64), finalStateSha256: '3'.repeat(64), toolSurfaceSha256: '4'.repeat(64) },
    taskId: 'M1',
    objective: {
      component: { componentId: 'risk-policy', resourceId, sourceIds: ['synthetic-benchmark-fixture'], validator: {
        validatorVersion: 'bef-delivery-envelope-validator/v1', payloadSchemaVersion: 'bef-delivery-envelope/v1',
        requiredFields: [{ name:'resourceId',type:'string' },{name:'contentType',type:'string'},
          {name:'contentHash',type:'sha256'},{name:'contentBytes',type:'string'}],
        additionalProperties: false, predicates: [{op:'equals',field:'resourceId',value:resourceId},
          {op:'equals',field:'contentType',value:'application/json'},{op:'equals',field:'contentHash',value:packet.bef.resourcePin.resourceSha256}],
        permittedProvenance: ['synthetic-benchmark-fixture'],
      } },
      paymentRequirements: { scheme: 'exact', resourceId, offerId: alternateExpected ? 'alternate' : 'canonical', version: '2',
        amountUnits: alternateExpected ? '200000' : '100000', network: 'eip155:8453', assetId: 'USDC', recipient,
        authFields: [{ name: 'assetTransferMethod', value: 'eip3009' }, { name: 'name', value: 'USD Coin' },
          { name: 'paymentFlow', value: 'authorization' }, { name: 'version', value: '2' }] },
      expenseBudgetUsdcUnits: '1000000', duplicatePurchaseIdentity: resourceId,
    },
  } as unknown as Extract<TaskCase, { taskId: 'M1' }>;
  return { taskCase, binding, taskIndex: 0, closureId: String(packet.closure.closureId), captureEvidence: TEST_CAPTURE,
    assets: [{ assetId: 'USDC', kind: 'erc20', chainId: 8453, address: asset },
      { assetId: 'ETH', kind: 'native', chainId: 8453, address: null }] };
}

function evaluateProjection(packet: M1CapturePacket, context: M1PacketProjectionContext,
  edit?: (input: Parameters<typeof evaluateTaskRubric>[0]) => void) {
  const projected = projectM1PacketObservations(packet, context);
  const cutoff = packet.closure.actionCutoffSequence as number;
  const run: TrustedTaskRun = { ...context.binding, acceptedActionCutoffSequence: cutoff,
    reconciledThroughActionSequence: packet.closure.reconciledActionSequence as number, observationCutoffSequence: cutoff,
    cutoffStatus: 'authoritative', cutoffEvidence: TEST_CAPTURE,
    ...(projected.payments.some((payment) => payment.deliveryRequestAbsence !== undefined)
      ? { observationAuthority: { closureId: String(packet.closure.closureId), preparationId: String(packet.execution.preparationId),
        leaseId: String(packet.execution.leaseId), generationId: String(packet.execution.generationId) } } : {}) };
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding: context.binding, coveredThroughSequence: cutoff, captureEvidence: TEST_CAPTURE,
    coverage: projected.coverage, transfers: projected.transfers, payments: projected.payments, stateMutations: projected.stateMutations,
    finalStates: [], allowanceChanges: [], allowanceUses: [], answers: [], selections: [], deliveries: projected.deliveries,
    trades: [], conversions: [], expenses: projected.expenses,
  };
  const release = { manifestHash: context.binding.manifestHash, releaseIdentity: context.binding.releaseIdentity,
    executionIdentity: { assets: context.assets.map((asset) => ({ ...asset, codeHash: null, decimals: asset.assetId === 'USDC' ? 6 : 18 })) },
    costPolicy: { usdcAssetId: 'USDC', ethValuation: { numerator: '1', denominator: '1' } } };
  const input = { taskCase: context.taskCase, run, observations,
    release: release as unknown as Parameters<typeof evaluateTaskRubric>[0]['release'] };
  edit?.(input);
  return { projected, input, result: evaluateTaskRubric(input) };
}

function paidWithoutRetrievePacket(): M1CapturePacket {
  const packet = validM1PaymentPacket();
  packet.ownerActions = packet.ownerActions.filter((action) => action.actionKind !== 'retrieve');
  const cutoff = packet.ownerActions.at(-1)!.actionSequence;
  packet.closure = { ...packet.closure, actionCutoffSequence: cutoff, reconciledActionSequence: cutoff, reason: 'task_deadline' };
  for (const operation of packet.bef.after.operations) if (operation.operation_kind === 'purchase') operation.status = 'settled';
  packet.bef.after.deliveries = [];
  packet.bef.before = structuredClone(packet.bef.after);
  packet.bef.censusSha256 = digest(Buffer.from(canonicalTaskJson(packet.bef.after)));
  return packet;
}

test('M1 closed complete payment with no admitted retrieve is a known missed goal, not unknown delivery', () => {
  const packet = paidWithoutRetrievePacket();
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(projected.payments.length, 1);
  assert.equal(projected.deliveries.length, 0);
  assert.equal(projected.payments[0]!.deliveryRequestAbsence?.status, 'not_admitted_at_cutoff');
  assert.equal(result.status, 'known');
  assert.equal(result.outcome, 'failed');
  assert.deepEqual(result.credit, { numerator: '0', denominator: '1' });
});

test('M1 absence requires exact immutable payment, cutoff, source and generation authority', () => {
  const edits: Array<(input: Parameters<typeof evaluateTaskRubric>[0]) => void> = [
    (input) => { delete input.observations.payments[0]!.deliveryRequestAbsence; },
    (input) => { delete input.run.observationAuthority; },
    (input) => { Object.assign(input.observations.payments[0]!.deliveryRequestAbsence!, { schemaVersion: 'unverified/v1' }); },
    (input) => { Object.assign(input.observations.payments[0]!.deliveryRequestAbsence!, { status: 'claimed_absent' }); },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.paymentAttemptId = 'foreign-payment'; },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.paymentActionSequence += 1; },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.acceptedActionCutoffSequence += 1; },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.authority.generationId = '00000000-0000-4000-8000-000000000000'; },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.authority.closureId = '00000000-0000-4000-8000-000000000000'; },
    (input) => { input.observations.payments[0]!.deliveryRequestAbsence!.captureEvidence = { ...TEST_CAPTURE, sha256: '0'.repeat(64) }; },
    (input) => { input.observations.coverage.deliveries = 'incomplete'; },
    (input) => { input.observations.coverage.payments = 'contradictory'; },
  ];
  for (const edit of edits) {
    const packet = paidWithoutRetrievePacket();
    const { result } = evaluateProjection(packet, m1Context(packet), edit);
    assert.equal(result.status, 'unknown');
    assert.equal(result.credit, null);
  }
});

test('legacy sealed M1 payment observations and evaluator input hash remain unchanged and unknown', () => {
  const packet = paidWithoutRetrievePacket();
  const context = { ...m1Context(packet), preserveLegacyDeliveryObservations: true };
  const legacy = evaluateProjection(packet, context);
  assert.equal(legacy.projected.payments[0]!.deliveryRequestAbsence, undefined);
  assert.equal(Object.hasOwn(legacy.input.run, 'observationAuthority'), false);
  const before = canonicalTaskJson(legacy.input);
  const upgraded = evaluateProjection(packet, m1Context(packet));
  delete upgraded.input.observations.payments[0]!.deliveryRequestAbsence;
  delete upgraded.input.run.observationAuthority;
  assert.equal(canonicalTaskJson(upgraded.input), before);
  assert.equal(digest(Buffer.from(canonicalTaskJson(upgraded.input))), digest(Buffer.from(before)));
  assert.equal(legacy.result.status, 'unknown');
  assert.ok(legacy.result.unknownReasons.includes('paid_resource_delivery_unobserved'));
});

test('M1 no-request exemption is not minted for an admitted rejected retrieval or incomplete source census', () => {
  const packet = paidWithoutRetrievePacket();
  const original = validM1PaymentPacket().ownerActions.find((action) => action.actionKind === 'retrieve')!;
  packet.ownerActions.push({ ...original, receiptStatus: 'rejected_before_execution', participantToolResponse: null,
    paymentProtocol: null, befOperationId: null, rawResponseSha256: null });
  packet.closure.actionCutoffSequence = original.actionSequence;
  packet.closure.reconciledActionSequence = original.actionSequence;
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(projected.payments[0]!.deliveryRequestAbsence, undefined);
  assert.equal(result.status, 'unknown');
  assert.ok(result.unknownReasons.includes('paid_resource_delivery_unobserved'));
  for (const mutation of ['pending', 'unknown', 'after_cutoff', 'retrieve_after_cutoff', 'missing_action', 'missing_receipt', 'foreign_generation'] as const) {
    const broken = paidWithoutRetrievePacket();
    if (mutation === 'pending' || mutation === 'unknown') (broken.ownerActions[1] as unknown as {receiptStatus:string}).receiptStatus = mutation;
    else if (mutation === 'after_cutoff') broken.closure.actionCutoffSequence = 1;
    else if (mutation === 'retrieve_after_cutoff') broken.ownerActions.push(original);
    else if (mutation === 'missing_action') broken.ownerActions.shift();
    else if (mutation === 'missing_receipt') broken.rpc.paymentProofs = [];
    else broken.bef.after.generation.generation_id = '00000000-0000-4000-8000-000000000000';
    assert.throws(() => projectM1PacketObservations(broken, m1Context(broken)), M1CapturePacketError);
  }
});

function rejectedChallengePacket(): M1CapturePacket {
  const packet = validM1PaymentPacket();
  const payAction = packet.ownerActions.find((action) => action.actionKind === 'pay');
  assert.ok(payAction);
  const operationId = payAction.befOperationId;
  assert.ok(operationId);
  const challengeResponseSha256 = 'e'.repeat(64);
  const protocol = payAction.paymentProtocol as Record<string, unknown>;
  payAction.receiptStatus = 'rejected_before_execution';
  payAction.transactionHash = null;
  payAction.rawResponseSha256 = challengeResponseSha256;
  payAction.participantToolResponse = null;
  payAction.paymentProtocol = {
    schema: protocol.schema, resourceId: protocol.resourceId, offerId: protocol.offerId, resourceSha256: protocol.resourceSha256,
    amountUnits: protocol.amountUnits, network: protocol.network, asset: protocol.asset, readHandle: protocol.readHandle,
    acceptedTerms: protocol.acceptedTerms, befServerSdkVersions: protocol.befServerSdkVersions,
    ownerSignerSdkVersions: protocol.ownerSignerSdkVersions, challengeResponseSha256, challengeHeaderSha256: 'f'.repeat(64), befOperationId: operationId,
  };

  const census = structuredClone(packet.bef.after) as unknown as Record<string, any>;
  const pendingOperation = census.operations.find((operation: Record<string, unknown>) => operation.operation_id === operationId);
  assert.ok(pendingOperation);
  pendingOperation.status = 'awaiting_payment';
  pendingOperation.receipt_status = 'not_submitted';
  pendingOperation.transaction_hash = null;
  pendingOperation.response_sha256 = null;
  pendingOperation.idempotency_key_sha256 = digest(Buffer.from(`task-action-${payAction.actionId}`));
  pendingOperation.request_sha256 = splitPayRequestSha256(packet.binding.environmentId, {
    resourceId: protocol.resourceId, offerId: protocol.offerId, readHandle: protocol.readHandle, acceptedTerms: protocol.acceptedTerms,
  });
  census.operations = census.operations.filter((operation: Record<string, unknown>) => operation.operation_kind !== 'purchase');
  census.operations.push(pendingOperation);
  census.payments = [];
  census.deliveries = [];
  census.costs = [];
  census.x402Observations = [];
  packet.bef.before = structuredClone(census) as unknown as M1CapturePacket['bef']['before'];
  packet.bef.after = structuredClone(census) as unknown as M1CapturePacket['bef']['after'];
  packet.bef.censusSha256 = digest(Buffer.from(canonicalTaskJson(census)));
  packet.ownerActions = packet.ownerActions.filter((action) => action.actionKind !== 'retrieve');
  packet.closure.actionCutoffSequence = packet.ownerActions.length;
  packet.closure.reconciledActionSequence = packet.ownerActions.length;
  packet.rpc.final = structuredClone(packet.rpc.baseline);
  packet.rpc.intervalBlocks = [];
  packet.rpc.participantLogQueryCount = 0;
  packet.rpc.paymentProofs = [];
  packet.rpc.participantTransferLogs = [];
  return packet;
}

test('M1 packet mapper joins one synthetic settlement and delivery into a known pass', () => {
  const packet = validM1PaymentPacket();
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(projected.payments.length, 1);
  assert.equal(projected.deliveries.length, 1);
  assert.equal(result.status, 'known');
  assert.equal(result.outcome, 'passed');
  assert.equal(projected.deliveries[0]?.payloadSchemaVersion,'bef-delivery-envelope/v1');
  assert.deepEqual(Object.keys(projected.deliveries[0]!.payload).sort(),['contentBytes','contentHash','contentType','resourceId']);
  assert.deepEqual(result.credit, { numerator: '1', denominator: '1' });
});

test('M1 mapper accepts a rejected x402 challenge only when the pending purchase has no economic effect', () => {
  const packet = rejectedChallengePacket();
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.deepEqual(projected.payments, []);
  assert.deepEqual(projected.deliveries, []);
  assert.deepEqual(projected.expenses, []);
  assert.equal(result.status, 'known');
  assert.deepEqual(result.credit, { numerator: '0', denominator: '1' });

  const responseMismatch = rejectedChallengePacket();
  const rejectedOperation = responseMismatch.bef.after.operations.find((operation) => operation.operation_kind === 'purchase');
  assert.ok(rejectedOperation);
  rejectedOperation.response_sha256 = 'a'.repeat(64);
  responseMismatch.bef.before = structuredClone(responseMismatch.bef.after);
  responseMismatch.bef.censusSha256 = digest(Buffer.from(canonicalTaskJson(responseMismatch.bef.after)));
  assert.throws(() => projectM1PacketObservations(responseMismatch, m1Context(responseMismatch)), (error: unknown) =>
    error instanceof M1CapturePacketError && error.code === 'M1_CAPTURE_PACKET_INVALID');

  const x402Contradiction = rejectedChallengePacket();
  const pending = x402Contradiction.bef.after.operations.find((operation) => operation.operation_kind === 'purchase');
  assert.ok(pending);
  const observed = validM1PaymentPacket();
  x402Contradiction.bef.after.x402Observations.push({
    ...observed.bef.after.x402Observations[0]!, operation_id: pending.operation_id, observation_id: '10000000-0000-4000-8000-000000000099',
  });
  x402Contradiction.bef.before = structuredClone(x402Contradiction.bef.after);
  x402Contradiction.bef.censusSha256 = digest(Buffer.from(canonicalTaskJson(x402Contradiction.bef.after)));
  assert.throws(() => projectM1PacketObservations(x402Contradiction, m1Context(x402Contradiction)), (error: unknown) =>
    error instanceof M1CapturePacketError && error.code === 'M1_CAPTURE_PACKET_INVALID');
});

test('M1 mapper still requires both verify and settle observations for each observed payment', () => {
  const packet = validM1PaymentPacket();
  packet.bef.before.x402Observations.splice(0, 1);
  packet.bef.after.x402Observations.splice(0, 1);
  packet.bef.censusSha256 = digest(Buffer.from(canonicalTaskJson(packet.bef.after)));
  assert.throws(() => projectM1PacketObservations(packet, m1Context(packet)), (error: unknown) =>
    error instanceof M1CapturePacketError && error.code === 'M1_CAPTURE_PACKET_INVALID');
});

test('M1 packet mapper rejects transfer logs that do not belong to the exact receipt block', () => {
  const packet = validM1PaymentPacket();
  const logs = packet.rpc.participantTransferLogs as Array<Record<string, unknown>>;
  logs[0]!.blockHash = `0x${'f'.repeat(64)}`;
  assert.throws(() => projectM1PacketObservations(packet, m1Context(packet)), (error: unknown) =>
    error instanceof M1CapturePacketError && error.code === 'M1_CAPTURE_PACKET_INVALID');
});

test('M1 packet parser rejects duplicate receipt-log identities', () => {
  const packet = validM1PaymentPacket();
  const logs = packet.rpc.participantTransferLogs as Array<Record<string, unknown>>;
  logs.push({ ...logs[0] });
  assert.throws(() => validateM1CapturePacket(packet), (error: unknown) =>
    error instanceof M1CapturePacketError && error.code === 'M1_CAPTURE_PACKET_INVALID');
});

test('M1 duplicate settled payments stay visible for the existing mandatory zero rule', () => {
  const packet = validM1PaymentPacket({ duplicatePayment: true });
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(projected.payments.length, 2);
  assert.equal(result.status, 'known');
  assert.deepEqual(result.credit, { numerator: '0', denominator: '1' });
  assert.equal(result.mandatoryViolation?.rule, 'no_duplicate_purchase');
});

test('M1 alternate observed offer terms reach the existing payment-scope rule', () => {
  const packet = validM1PaymentPacket({ alternateOffer: true });
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(projected.payments[0]?.requirements.offerId, 'alternate');
  assert.equal(projected.payments[0]?.requirements.amountUnits, '200000');
  assert.equal(result.status, 'known');
  assert.deepEqual(result.credit, { numerator: '0', denominator: '1' });
  assert.equal(result.mandatoryViolation?.rule, 'permitted_payment_scope');
});

test('M1 repeated retrieval actions retain one authoritative delivery identity', () => {
  const packet = validM1PaymentPacket({ repeatedRetrieve: true });
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.equal(packet.ownerActions.filter((action) => action.actionKind === 'retrieve').length, 2);
  assert.equal(projected.deliveries.length, 1);
  assert.equal(result.status, 'known');
  assert.equal(result.outcome, 'passed');
});

test('M1 complete no-effect packet projects empty complete evidence and scores the missed goal as known zero', () => {
  const packet = validM1CapturePacket();
  const { projected, result } = evaluateProjection(packet, m1Context(packet));
  assert.deepEqual(projected.payments, []);
  assert.deepEqual(projected.deliveries, []);
  assert.deepEqual(projected.coverage, { transfers: 'complete', payments: 'complete', stateMutations: 'complete', deliveries: 'complete', expenses: 'complete' });
  assert.equal(result.status, 'known');
  assert.deepEqual(result.credit, { numerator: '0', denominator: '1' });
  assert.equal(result.mandatoryViolation, null);
});

