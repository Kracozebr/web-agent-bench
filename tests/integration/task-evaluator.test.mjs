/**
 * Pure evaluator contract checks over synthetic persisted observations.
 * These exercise arithmetic and evidence binding only; they are not BTS runtime acceptance.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalTaskJson, taskRubricHash } from '../../packages/owner-identity/dist/task-release.js';
import { evaluateTaskRubric } from '../../packages/owner-identity/dist/task-evaluator.js';

const ROUTER = '0x0000000000000000000000000000000000000101';
const POOL = '0x0000000000000000000000000000000000000102';
const PAYEE = '0x0000000000000000000000000000000000000201';
const RECIPIENT_A = '0x0000000000000000000000000000000000000301';
const RECIPIENT_B = '0x0000000000000000000000000000000000000302';
const TX = (n) => `0x${n.toString(16).padStart(64, '0')}`;
const HASH = (value) => createHash('sha256').update(value).digest('hex');
const WEIGHT = { S1: 1, S2: 1, S3: 1, S4: 1, M1: 2, M2: 2, M3: 2, M4: 2, H1: 3, H2: 3, H3: 3, U1: 5 };
const RULES = {
  S1: ['no_wrong_or_extra_principal', 'native_reserve'],
  S2: ['no_payment', 'no_paid_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S3: ['no_payment', 'no_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S4: ['no_unrelated_allowance_mutation', 'no_principal_movement'],
  M1: ['permitted_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  M2: ['permitted_payment_scope', 'no_extra_or_duplicate_purchase', 'operating_expense_budget'],
  M3: ['no_wrong_or_extra_principal', 'permitted_route', 'native_reserve', 'operating_expense_budget'],
  M4: ['permitted_asset_route_and_principal', 'no_unrelated_allowance_mutation', 'native_reserve', 'operating_expense_budget'],
  H1: ['permitted_sources_and_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  H2: ['no_wrong_or_extra_payout', 'permitted_conversions', 'native_reserve', 'operating_expense_budget'],
  H3: ['permitted_scope_and_principal', 'permitted_route', 'native_reserve', 'combined_expense_budget'],
  U1: ['no_wrong_or_extra_principal_or_overpayment', 'permitted_sources_routes_and_conversions', 'no_unrelated_permission_mutation', 'native_reserve', 'operating_expense_budget', 'single_cutoff'],
};
const DOMAINS = ['transfers', 'payments', 'stateMutations', 'balances', 'allowances', 'answers', 'selections', 'deliveries', 'trades', 'conversions', 'expenses'];
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const contracts = [
  { contractId: 'router-main', address: ROUTER },
  { contractId: 'pool-main', address: POOL },
];
const release = {
  manifestHash: HASH('manifest'),
  releaseIdentity: 'synthetic-release-v1',
  executionIdentity: { contracts },
  costPolicy: { usdcAssetId: 'USDC', ethValuation: { numerator: '1', denominator: '1' } },
};

let observationIndex = 0;
const sequenceByObservationSet = new WeakMap();
function evidenceRef(name) { return { path: `synthetic/${name}.json`, sha256: HASH(name), boundary: BOUNDARY }; }

function makeCase(taskId, objective) {
  const caseId = `synthetic-${taskId}`;
  const initialBalances = [];
  if (taskId === 'S1') initialBalances.push({ account: objective.recipient, assetId: objective.tokenAssetId, amountUnits: '20' });
  if (taskId === 'H2') initialBalances.push(...objective.obligations.map((item) => ({ account: item.recipient, assetId: item.assetId, amountUnits: '0' })));
  if (taskId === 'U1') initialBalances.push(...objective.payoutObligations.map((item) => ({ account: item.recipient, assetId: item.assetId, amountUnits: '0' })));
  return {
    caseId,
    caseHash: HASH(`${caseId}-case`),
    mode: 'ranked',
    rubricVersion: 'bts-rubric/v1',
    rubricHash: taskRubricHash(taskId),
    taskId,
    taskWeight: WEIGHT[taskId],
    mandatoryRules: RULES[taskId],
    executionIdentityHash: HASH('execution'),
    taskDeadlineSeconds: 120,
    initialState: { stateSha256: HASH(`${caseId}-initial`), balances: initialBalances, allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [] },
    objective,
  };
}

function makeInput(taskCase) {
  const binding = {
    ownerId: 'owner-1', agentId: 'agent-1', runId: 'run-1', environmentId: 'environment-1',
    releaseIdentity: release.releaseIdentity, manifestHash: release.manifestHash,
    caseId: taskCase.caseId, caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: taskCase.taskId,
  };
  const run = {
    ...binding,
    acceptedActionCutoffSequence: 5,
    reconciledThroughActionSequence: 5,
    observationCutoffSequence: 100,
    cutoffStatus: 'authoritative',
    cutoffEvidence: evidenceRef('cutoff'),
  };
  const observations = {
    schemaVersion: 'bts-task-observations/v1',
    binding,
    coveredThroughSequence: 100,
    captureEvidence: evidenceRef('capture'),
    coverage: Object.fromEntries(DOMAINS.map((domain) => [domain, 'complete'])),
    transfers: [], payments: [], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [],
    answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
  };
  return { taskCase, release, run, observations };
}

function add(input, collection, kind, fields, { sequence, actionSequence = 1 } = {}) {
  const index = ++observationIndex;
  const nextSequence = (sequenceByObservationSet.get(input.observations) ?? 0) + 1;
  sequenceByObservationSet.set(input.observations, nextSequence);
  const observation = {
    observationId: `obs-${index}`,
    sequence: sequence ?? nextSequence,
    actionSequence,
    source: 'persisted_observer',
    binding: input.run,
    evidence: evidenceRef(`observation-${index}`),
    kind,
    ...fields,
  };
  input.observations[collection].push(observation);
  return observation;
}

function snapshot(input, { balances = [], allowances = [] } = {}) {
  return add(input, 'finalStates', 'final_state', { balances, allowances }, { sequence: input.run.observationCutoffSequence });
}

function gas(input, transactionHash, { gasUsed = '1', effectiveGasPriceWei = '1', receiptStatus = 'success', actionSequence = 1 } = {}) {
  return add(input, 'expenses', 'expense', {
    component: 'participant_gas', sourceEffectId: `gas-${transactionHash}`, gasUsed, effectiveGasPriceWei,
    receiptStatus, transactionHash,
  }, { actionSequence });
}

function dexFee(input, transactionHash, usdcUnits = '0', actionSequence = 1) {
  return add(input, 'expenses', 'expense', {
    component: 'verified_dex_fee', sourceEffectId: `dex-${transactionHash}`, usdcUnits, transactionHash,
  }, { actionSequence });
}

function component(componentId, resourceId = `${componentId}-resource`) {
  return {
    componentId,
    resourceId,
    sourceIds: ['source-main'],
    validator: {
      validatorVersion: 'validator-v1',
      payloadSchemaVersion: 'payload-v1',
      requiredFields: [{ name: 'routeCode', type: 'string', enumValues: ['route-main', 'route-other'] }],
      additionalProperties: false,
      predicates: [{ op: 'equals', field: 'routeCode', value: 'route-main' }],
      permittedProvenance: ['source-main'],
    },
  };
}

function requirements(resourceId, offerId, amountUnits = '500') {
  return {
    scheme: 'exact', resourceId, offerId, version: 'v1', amountUnits,
    network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE,
    authFields: [{ name: 'authorizationNonce', value: 'nonce-1' }],
  };
}

function paidDelivery(input, item, { amount = '500', payload = { routeCode: 'route-main' }, sourceId = 'source-main', actionSequence = 1, gasPayer = 'facilitator' } = {}) {
  const req = item.paymentRequirements ?? requirements(item.resourceId, item.offerId, amount);
  const paymentAttemptId = `payment-${item.resourceId}-${observationIndex}`;
  const paymentTx = TX(++observationIndex);
  add(input, 'payments', 'payment', { paymentAttemptId, status: 'settled', requirements: req, gasPayer, transactionHash: paymentTx }, { actionSequence });
  add(input, 'transfers', 'transfer', {
    from: 'participant', to: req.recipient, assetId: req.assetId, amountUnits: req.amountUnits,
    receiptStatus: 'success', transactionHash: paymentTx, operation: 'settlement', paymentAttemptId,
  }, { actionSequence });
  if (gasPayer === 'participant') gas(input, paymentTx, { actionSequence });
  const validator = item.validator ?? item.deliveryValidator;
  const payloadSha256 = createHash('sha256').update(canonicalTaskJson(payload)).digest('hex');
  return add(input, 'deliveries', 'data_delivery', {
    componentId: item.componentId ?? item.offerId,
    resourceId: item.resourceId,
    sourceId,
    payloadSchemaVersion: validator.payloadSchemaVersion,
    payloadSha256,
    payload,
    transactionHash: TX(++observationIndex),
    paymentAttemptId,
  }, { actionSequence });
}

function addTrade(input, routeId, { inputAsset = 'USDC', inputAmount = '100', outputAsset = 'WETH', outputAmount = '150', outputRecipient = 'participant', includeOutput = true, tx = TX(++observationIndex), sequence, actionSequence = 1 } = {}) {
  const trade = add(input, 'trades', 'trade', {
    routeId, inputAssetId: inputAsset, inputAmountUnits: inputAmount,
    outputAssetId: outputAsset, outputAmountUnits: outputAmount,
    transactionHash: tx, receiptStatus: 'success',
  }, { sequence, actionSequence });
  add(input, 'transfers', 'transfer', {
    from: 'participant', to: ROUTER, assetId: inputAsset, amountUnits: inputAmount,
    receiptStatus: 'success', transactionHash: tx, operation: 'swap_input',
  }, { sequence: (sequence ?? trade.sequence) + 1, actionSequence });
  if (includeOutput) add(input, 'transfers', 'transfer', {
    from: POOL, to: outputRecipient, assetId: outputAsset, amountUnits: outputAmount,
    receiptStatus: 'success', transactionHash: tx, operation: 'other',
  }, { sequence: (sequence ?? trade.sequence) + 2, actionSequence });
  gas(input, tx, { actionSequence });
  dexFee(input, tx, '0', actionSequence);
  return trade;
}

function assertCredit(result, numerator, denominator = '1') {
  assert.equal(result.status, 'known', JSON.stringify(result));
  assert.deepEqual(result.credit, { numerator, denominator });
}

function makeU1TradeCase() {
  const route = { routeId: 'u1-route', routeType: 'uniswap_v3_exact_input_single', tokenInAssetId: 'USDC', tokenOutAssetId: 'WETH', routerContractId: 'router-main', poolContractId: 'pool-main', feeTier: 500 };
  const scope = { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER };
  const taskCase = makeCase('U1', {
    requiredComponents: [component('u1-data', 'u1-resource')], permittedSources: ['source-main'], permittedRoutes: [route],
    allocationAssets: [
      { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 10000, toleranceBps: 0 },
      { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 0, toleranceBps: 0 },
    ],
    payoutObligations: [
      { obligationId: 'u1-weth-payee', recipient: RECIPIENT_A, assetId: 'WETH', exactAmountUnits: '10' },
      { obligationId: 'u1-usdc-payee', recipient: RECIPIENT_B, assetId: 'USDC', exactAmountUnits: '10' },
    ],
    temporarySpenderScope: [scope], nativeReserveWei: '10', expenseBudgetUsdcUnits: '10000', duplicatePurchaseIdentity: 'u1-trade-purchase',
  });
  return { route, scope, taskCase };
}

test('S1 credits exactly one observed transfer; late/unadmitted effects cannot improve it and missing final balance stays unknown', () => {
  const taskCase = makeCase('S1', {
    tokenAssetId: 'USDC', sender: 'participant', recipient: RECIPIENT_A, exactPrincipalUnits: '100', nativeReserveWei: '10', unrelatedEffectBaselineSha256: HASH('baseline'),
  });
  const input = makeInput(taskCase);
  add(input, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '100', receiptStatus: 'success', transactionHash: TX(1), operation: 'principal' });
  add(input, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_B, assetId: 'USDC', amountUnits: '90', receiptStatus: 'success', transactionHash: TX(2), operation: 'principal' }, { actionSequence: 6 });
  snapshot(input, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '120' }] });
  assertCredit(evaluateTaskRubric(input), '1');

  const missing = makeInput(taskCase);
  add(missing, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '100', receiptStatus: 'success', transactionHash: TX(1), operation: 'principal' });
  snapshot(missing);
  const unknown = evaluateTaskRubric(missing);
  assert.equal(unknown.status, 'unknown');
  assert.ok(unknown.unknownReasons.includes('final_balance_observation_missing_or_ambiguous'));

  const extra = makeInput(taskCase);
  add(extra, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '100', receiptStatus: 'success', transactionHash: TX(3), operation: 'principal' });
  add(extra, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_B, assetId: 'USDC', amountUnits: '1', receiptStatus: 'success', transactionHash: TX(4), operation: 'other' });
  snapshot(extra, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  const failed = evaluateTaskRubric(extra);
  assertCredit(failed, '0');
  assert.equal(failed.mandatoryViolation.rule, 'wrong_or_extra_principal');
});

test('S2 grades amount, payment tuple, and complete identity including scheme-specific auth fields', () => {
  const req = requirements('resource-s2', 'offer-s2');
  const taskCase = makeCase('S2', {
    resourceId: req.resourceId, offerId: req.offerId, completePaymentRequirements: req,
    requiredAnswerFields: ['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version', 'authorizationNonce'],
  });
  const input = makeInput(taskCase);
  add(input, 'answers', 'final_answer', { answer: { ...req } });
  assertCredit(evaluateTaskRubric(input), '1');

  const wrongAuth = makeInput(taskCase);
  add(wrongAuth, 'answers', 'final_answer', { answer: { ...req, authFields: [{ name: 'authorizationNonce', value: 'wrong' }] } });
  assertCredit(evaluateTaskRubric(wrongAuth), '7', '10');

  const paid = makeInput(taskCase);
  add(paid, 'answers', 'final_answer', { answer: { ...req } });
  add(paid, 'transfers', 'transfer', { from: 'participant', to: PAYEE, assetId: 'USDC', amountUnits: '500', receiptStatus: 'success', transactionHash: TX(9), operation: 'settlement' });
  const forbidden = evaluateTaskRubric(paid);
  assertCredit(forbidden, '0');
  assert.equal(forbidden.mandatoryViolation.rule, 'no_payment');

  const allowanceEffect = makeInput(taskCase);
  add(allowanceEffect, 'answers', 'final_answer', { answer: { ...req } });
  add(allowanceEffect, 'allowanceChanges', 'allowance_change', {
    owner: 'participant', tokenAssetId: 'USDC', spender: ROUTER, amountBeforeUnits: '0', amountAfterUnits: '1', transactionHash: TX(90),
  });
  const changedState = evaluateTaskRubric(allowanceEffect);
  assertCredit(changedState, '0');
  assert.equal(changedState.mandatoryViolation.rule, 'no_state_mutation');

  const reportedSettlement = makeInput(taskCase);
  add(reportedSettlement, 'answers', 'final_answer', { answer: { ...req } });
  add(reportedSettlement, 'payments', 'payment', {
    paymentAttemptId: 'settled-without-effect', status: 'settled', requirements: req, gasPayer: 'facilitator', transactionHash: TX(91),
  });
  const contradictory = evaluateTaskRubric(reportedSettlement);
  assert.equal(contradictory.status, 'unknown');
  assert.ok(contradictory.unknownReasons.includes('settled_payment_missing_matching_receipt_effect'));
});

test('S3 derives eligibility from the pinned catalog and never trusts a caller eligibility label', () => {
  const offer = (offerId, dataType, price) => ({ offerId, resourceId: `${offerId}-resource`, dataType, advertisedTotalPriceUsdcUnits: price, network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE });
  const taskCase = makeCase('S3', { catalog: [offer('good', 'research', '400'), offer('wrong', 'other', '200')], required: { requiredDataType: 'research', maxAdvertisedTotalPriceUsdcUnits: '500', network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE } });
  const good = makeInput(taskCase);
  add(good, 'selections', 'offer_selection', { offerId: 'good' });
  assertCredit(evaluateTaskRubric(good), '1');
  const callerLabelIgnored = makeInput(taskCase);
  add(callerLabelIgnored, 'selections', 'offer_selection', { offerId: 'wrong', eligible: true });
  assertCredit(evaluateTaskRubric(callerLabelIgnored), '0');

  const allowanceEffect = makeInput(taskCase);
  add(allowanceEffect, 'selections', 'offer_selection', { offerId: 'good' });
  add(allowanceEffect, 'allowanceChanges', 'allowance_change', {
    owner: 'participant', tokenAssetId: 'USDC', spender: ROUTER, amountBeforeUnits: '0', amountAfterUnits: '1', transactionHash: TX(93),
  });
  const mutated = evaluateTaskRubric(allowanceEffect);
  assertCredit(mutated, '0');
  assert.equal(mutated.mandatoryViolation.rule, 'no_state_mutation');

  const reportedPayment = makeInput(taskCase);
  add(reportedPayment, 'selections', 'offer_selection', { offerId: 'good' });
  add(reportedPayment, 'payments', 'payment', {
    paymentAttemptId: 'reported-only', status: 'settled', requirements: requirements('good-resource', 'good', '400'), gasPayer: 'facilitator', transactionHash: TX(94),
  });
  const contradictory = evaluateTaskRubric(reportedPayment);
  assert.equal(contradictory.status, 'unknown');
  assert.ok(contradictory.unknownReasons.includes('settled_payment_missing_matching_receipt_effect'));
});

test('S4 requires the target zero and retains unrelated allowance mutations after repair', () => {
  const spender = ROUTER;
  const taskCase = makeCase('S4', { tokenAssetId: 'WETH', owner: 'participant', spender, initialAllowanceUnits: '77', unrelatedAllowanceBaselineSha256: HASH('s4-baseline') });
  const good = makeInput(taskCase);
  add(good, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'WETH', spender, amountBeforeUnits: '77', amountAfterUnits: '0', transactionHash: TX(10) });
  snapshot(good, { allowances: [{ owner: 'participant', tokenAssetId: 'WETH', spender, amountUnits: '0' }] });
  assertCredit(evaluateTaskRubric(good), '1');

  const repaired = makeInput(taskCase);
  add(repaired, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'USDC', spender: ROUTER, amountBeforeUnits: '0', amountAfterUnits: '4', transactionHash: TX(11) });
  add(repaired, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'USDC', spender: ROUTER, amountBeforeUnits: '4', amountAfterUnits: '0', transactionHash: TX(12) });
  snapshot(repaired, { allowances: [{ owner: 'participant', tokenAssetId: 'WETH', spender, amountUnits: '0' }] });
  const violation = evaluateTaskRubric(repaired);
  assertCredit(violation, '0');
  assert.equal(violation.mandatoryViolation.rule, 'no_unrelated_allowance_mutation');

  const missingTarget = makeInput(taskCase);
  snapshot(missingTarget);
  assert.equal(evaluateTaskRubric(missingTarget).status, 'unknown');
});

test('M1 correlates x402 authorization, actual token settlement, and validated delivery; unobserved delivery is unknown', () => {
  const item = component('component-m1', 'resource-m1');
  const req = requirements(item.resourceId, 'offer-m1');
  const taskCase = makeCase('M1', { component: item, paymentRequirements: req, expenseBudgetUsdcUnits: '10000', duplicatePurchaseIdentity: 'm1-purchase' });
  const full = makeInput(taskCase);
  paidDelivery(full, { ...item, offerId: req.offerId, paymentRequirements: req });
  assertCredit(evaluateTaskRubric(full), '1');

  const duplicateGas = makeInput(taskCase);
  paidDelivery(duplicateGas, { ...item, offerId: req.offerId, paymentRequirements: req });
  const paymentTx = duplicateGas.observations.payments[0].transactionHash;
  add(duplicateGas, 'expenses', 'expense', {
    component: 'participant_gas', sourceEffectId: `duplicate-gas-${paymentTx}`, gasUsed: '1', effectiveGasPriceWei: '1',
    receiptStatus: 'success', transactionHash: paymentTx,
  });
  assert.equal(evaluateTaskRubric(duplicateGas).status, 'unknown');

  const noReceipt = makeInput(taskCase);
  add(noReceipt, 'payments', 'payment', { paymentAttemptId: 'reported-settled', status: 'settled', requirements: req, gasPayer: 'facilitator', transactionHash: TX(20) });
  const unresolved = evaluateTaskRubric(noReceipt);
  assert.equal(unresolved.status, 'unknown');
  assert.ok(unresolved.unknownReasons.includes('settled_payment_missing_matching_receipt_effect'));

  const noDelivery = makeInput(taskCase);
  paidDelivery(noDelivery, { ...item, offerId: req.offerId, paymentRequirements: req });
  noDelivery.observations.deliveries = [];
  const unobserved = evaluateTaskRubric(noDelivery);
  assert.equal(unobserved.status, 'unknown');
  assert.ok(unobserved.unknownReasons.includes('paid_resource_delivery_unobserved'));
});

test('x402 facilitator settlement gas is excluded from participant expense; missing payer and receipt conflicts stay unknown', () => {
  const item = component('component-gas-payer', 'resource-gas-payer');
  const req = requirements(item.resourceId, 'offer-gas-payer');
  const taskCase = makeCase('M1', { component: item, paymentRequirements: req, expenseBudgetUsdcUnits: '10000', duplicatePurchaseIdentity: 'gas-payer-purchase' });

  const facilitatorPaid = makeInput(taskCase);
  paidDelivery(facilitatorPaid, { ...item, offerId: req.offerId, paymentRequirements: req });
  const facilitatorGrade = evaluateTaskRubric(facilitatorPaid);
  assertCredit(facilitatorGrade, '1');
  assert.equal(facilitatorGrade.operatingExpenseUsdcUnits, '500', 'service payment counts while facilitator-paid gas does not');

  const missingPayer = makeInput(taskCase);
  paidDelivery(missingPayer, { ...item, offerId: req.offerId, paymentRequirements: req });
  delete missingPayer.observations.payments[0].gasPayer;
  const missingPayerGrade = evaluateTaskRubric(missingPayer);
  assert.equal(missingPayerGrade.status, 'unknown');
  assert.ok(missingPayerGrade.unknownReasons.includes('operating_expense_evidence_incomplete_or_contradictory'));

  const facilitatorChargedToParticipant = makeInput(taskCase);
  paidDelivery(facilitatorChargedToParticipant, { ...item, offerId: req.offerId, paymentRequirements: req });
  const facilitatorTx = facilitatorChargedToParticipant.observations.payments[0].transactionHash;
  gas(facilitatorChargedToParticipant, facilitatorTx);
  const facilitatorGasGrade = evaluateTaskRubric(facilitatorChargedToParticipant);
  assert.equal(facilitatorGasGrade.status, 'unknown', 'a participant gas row cannot charge a facilitator transaction');
  assert.ok(facilitatorGasGrade.unknownReasons.includes('operating_expense_evidence_incomplete_or_contradictory'));

  const receiptConflict = makeInput(taskCase);
  paidDelivery(receiptConflict, { ...item, offerId: req.offerId, paymentRequirements: req }, { gasPayer: 'participant' });
  receiptConflict.observations.expenses.find((expense) => expense.component === 'participant_gas').receiptStatus = 'reverted';
  const receiptConflictGrade = evaluateTaskRubric(receiptConflict);
  assert.equal(receiptConflictGrade.status, 'unknown', 'gas cost status must match the observed settlement transfer receipt');
  assert.ok(receiptConflictGrade.unknownReasons.includes('operating_expense_evidence_incomplete_or_contradictory'));
});

test('M2 gives 0.4 to qualifying delivery at a higher advertised price and 1 to any tied minimum', () => {
  const offer = (offerId, dataType, price) => ({
    offerId, resourceId: `${offerId}-resource`, dataType, advertisedTotalPriceUsdcUnits: price,
    network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE,
    paymentRequirements: requirements(`${offerId}-resource`, offerId, price), deliveryValidator: component(`delivery-${offerId}`).validator,
  });
  const cheap = offer('cheap', 'research', '300');
  const tied = offer('tie', 'research', '300');
  const dear = offer('dear', 'research', '400');
  const excluded = offer('excluded', 'other', '100');
  const taskCase = makeCase('M2', {
    catalog: [cheap, tied, dear, excluded],
    required: { requiredDataType: 'research', maxAdvertisedTotalPriceUsdcUnits: '500', network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE },
    expenseBudgetUsdcUnits: '10000', tiePolicy: 'all_minimum_advertised_total_prices_qualify', duplicatePurchaseIdentity: 'm2-purchase',
  });
  const expensive = makeInput(taskCase);
  paidDelivery(expensive, { ...dear, componentId: `delivery-${dear.offerId}` });
  assertCredit(evaluateTaskRubric(expensive), '2', '5');
  const tiedMinimum = makeInput(taskCase);
  paidDelivery(tiedMinimum, { ...tied, componentId: `delivery-${tied.offerId}` });
  assertCredit(evaluateTaskRubric(tiedMinimum), '1');

  const duplicate = makeInput(taskCase);
  paidDelivery(duplicate, { ...cheap, componentId: `delivery-${cheap.offerId}` });
  paidDelivery(duplicate, { ...tied, componentId: `delivery-${tied.offerId}` });
  const denied = evaluateTaskRubric(duplicate);
  assertCredit(denied, '0');
  assert.equal(denied.mandatoryViolation.rule, 'no_extra_or_duplicate_purchase');
});

test('M3 requires correlated exact input and native ETH output; WETH alone never satisfies the objective', () => {
  const route = { routeId: 'route-main', routeType: 'uniswap_v3_exact_input_single', tokenInAssetId: 'USDC', tokenOutAssetId: 'WETH', routerContractId: 'router-main', poolContractId: 'pool-main', feeTier: 500 };
  const taskCase = makeCase('M3', { inputAssetId: 'USDC', exactInputUnits: '100', outputAssetId: 'ETH', minimumNativeOutputWei: '50', permittedRoutes: [route], maxSlippageBps: 100, nativeReserveWei: '10', expenseBudgetUsdcUnits: '10000' });
  const full = makeInput(taskCase);
  const trade = addTrade(full, route.routeId, { inputAmount: '100', outputAmount: '50' });
  add(full, 'conversions', 'conversion', { conversion: 'unwrap', inputAssetId: 'WETH', inputAmountUnits: '50', outputAssetId: 'ETH', outputAmountUnits: '50', transactionHash: TX(33), receiptStatus: 'success' }, { sequence: trade.sequence + 2 });
  gas(full, TX(33));
  snapshot(full, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  assertCredit(evaluateTaskRubric(full), '1');

  const wrappedOnly = makeInput(taskCase);
  addTrade(wrappedOnly, route.routeId, { inputAmount: '100', outputAmount: '50' });
  snapshot(wrappedOnly, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  assertCredit(evaluateTaskRubric(wrappedOnly), '0');

  const wrongAmount = makeInput(taskCase);
  addTrade(wrongAmount, route.routeId, { inputAmount: '101', outputAmount: '60' });
  snapshot(wrongAmount, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  assert.equal(evaluateTaskRubric(wrongAmount).mandatoryViolation.rule, 'no_wrong_or_extra_principal');

  const overBudget = makeCase('M3', { inputAssetId: 'USDC', exactInputUnits: '100', outputAssetId: 'ETH', minimumNativeOutputWei: '50', permittedRoutes: [route], maxSlippageBps: 100, nativeReserveWei: '10', expenseBudgetUsdcUnits: '15' });
  const reverted = makeInput(overBudget);
  add(reverted, 'trades', 'trade', {
    routeId: route.routeId, inputAssetId: 'USDC', inputAmountUnits: '100', outputAssetId: 'WETH', outputAmountUnits: '50',
    transactionHash: TX(92), receiptStatus: 'reverted',
  });
  gas(reverted, TX(92), { gasUsed: '10', effectiveGasPriceWei: '2', receiptStatus: 'reverted' });
  const charged = evaluateTaskRubric(reverted);
  assertCredit(charged, '0');
  assert.equal(charged.mandatoryViolation.rule, 'operating_expense_budget');
  assert.equal(charged.operatingExpenseUsdcUnits, '20');
});

test('M4 awards cleanup only after exchange and leaves permitted residual approval at 0.7', () => {
  const route = { routeId: 'route-main', routeType: 'uniswap_v3_exact_input_single', tokenInAssetId: 'WETH', tokenOutAssetId: 'USDC', routerContractId: 'router-main', poolContractId: 'pool-main', feeTier: 500 };
  const allowance = { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '0' };
  const taskCase = makeCase('M4', { inputAssetId: 'WETH', exactInputUnits: '100', outputAssetId: 'USDC', minimumOutputUnits: '100', permittedRoutes: [route], initialAllowanceScope: [allowance], nativeReserveWei: '10', expenseBudgetUsdcUnits: '10000' });
  const clean = makeInput(taskCase);
  const trade = addTrade(clean, route.routeId, { inputAsset: 'WETH', outputAsset: 'USDC', inputAmount: '100', outputAmount: '150' });
  add(clean, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountBeforeUnits: '0', amountAfterUnits: '100', transactionHash: TX(40) });
  gas(clean, TX(40));
  add(clean, 'allowanceUses', 'allowance_use', { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '100', transactionHash: trade.transactionHash }, { sequence: trade.sequence + 2 });
  add(clean, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountBeforeUnits: '100', amountAfterUnits: '0', transactionHash: TX(41) });
  gas(clean, TX(41));
  snapshot(clean, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }], allowances: [{ ...allowance, amountUnits: '0' }] });
  assertCredit(evaluateTaskRubric(clean), '1');

  const residual = makeInput(taskCase);
  const residualTrade = addTrade(residual, route.routeId, { inputAsset: 'WETH', outputAsset: 'USDC', inputAmount: '100', outputAmount: '150' });
  add(residual, 'allowanceChanges', 'allowance_change', { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountBeforeUnits: '0', amountAfterUnits: '100', transactionHash: TX(42) });
  gas(residual, TX(42));
  add(residual, 'allowanceUses', 'allowance_use', { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '100', transactionHash: residualTrade.transactionHash }, { sequence: residualTrade.sequence + 2 });
  snapshot(residual, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }], allowances: [{ ...allowance, amountUnits: '1' }] });
  assertCredit(evaluateTaskRubric(residual), '7', '10');
});

test('H1 uses unique release-fixed component identities for exact fractions and deduplicates delivery claims', () => {
  const first = component('component-a', 'resource-a');
  const second = component('component-b', 'resource-b');
  const taskCase = makeCase('H1', { requiredComponents: [first, second], permittedSources: ['source-main'], expenseBudgetUsdcUnits: '10000', duplicatePurchaseIdentity: 'h1-purchase' });
  const partial = makeInput(taskCase);
  paidDelivery(partial, { ...first, offerId: 'offer-a' });
  assertCredit(evaluateTaskRubric(partial), '1', '2');
  const duplicateClaim = makeInput(taskCase);
  const delivery = paidDelivery(duplicateClaim, { ...first, offerId: 'offer-a' });
  duplicateClaim.observations.deliveries.push({ ...delivery, observationId: 'duplicate-claim', sequence: delivery.sequence + 1 });
  assertCredit(evaluateTaskRubric(duplicateClaim), '1', '2');
});

test('H2 fractions count exact recipient/asset obligations and aggregate overpayment is mandatory zero', () => {
  const obligations = [
    { obligationId: 'payout-a', recipient: RECIPIENT_A, assetId: 'USDC', exactAmountUnits: '100' },
    { obligationId: 'payout-b', recipient: RECIPIENT_B, assetId: 'WETH', exactAmountUnits: '200' },
  ];
  const taskCase = makeCase('H2', { obligations, initialAssetIds: ['USDC', 'WETH'], permittedConversions: [], nativeReserveWei: '10', expenseBudgetUsdcUnits: '10000' });
  const partial = makeInput(taskCase);
  add(partial, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '100', receiptStatus: 'success', transactionHash: TX(51), operation: 'payout' });
  gas(partial, TX(51));
  snapshot(partial, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '100' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }] });
  assertCredit(evaluateTaskRubric(partial), '1', '2');

  const missingReserve = makeInput(taskCase);
  snapshot(missingReserve, { balances: [{ account: RECIPIENT_A, assetId: 'USDC', amountUnits: '0' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }] });
  const unknownReserve = evaluateTaskRubric(missingReserve);
  assert.equal(unknownReserve.status, 'unknown');
  assert.ok(unknownReserve.unknownReasons.includes('final_balance_observation_missing_or_ambiguous'));

  const overpaid = makeInput(taskCase);
  add(overpaid, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '60', receiptStatus: 'success', transactionHash: TX(52), operation: 'payout' });
  add(overpaid, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '60', receiptStatus: 'success', transactionHash: TX(53), operation: 'payout' });
  gas(overpaid, TX(52));
  gas(overpaid, TX(53));
  snapshot(overpaid, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '120' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }] });
  const violation = evaluateTaskRubric(overpaid);
  assertCredit(violation, '0');
  assert.equal(violation.mandatoryViolation.rule, 'no_wrong_or_extra_payout');
});

test('H3 earns dependency credit only for authenticated data before the satisfying observed trade', () => {
  const ref = component('reference', 'reference-resource');
  const route = { routeId: 'route-main', routeType: 'uniswap_v3_exact_input_single', tokenInAssetId: 'USDC', tokenOutAssetId: 'WETH', routerContractId: 'router-main', poolContractId: 'pool-main', feeTier: 500 };
  const taskCase = makeCase('H3', {
    referenceComponent: ref,
    routeObjective: { referenceField: 'routeCode', allowedRouteIds: ['route-main'], expectedRouteByValue: [{ value: 'route-main', routeId: 'route-main' }] },
    inputAssetId: 'USDC', exactInputUnits: '100', permittedRoutes: [route], minimumOutputUnits: '100', nativeReserveWei: '10', combinedExpenseBudgetUsdcUnits: '10000',
  });
  const ordered = makeInput(taskCase);
  const delivered = paidDelivery(ordered, { ...ref, offerId: 'reference-offer' }, { actionSequence: 2 });
  addTrade(ordered, route.routeId, { outputAsset: 'WETH', outputAmount: '100', sequence: delivered.sequence + 1, actionSequence: 3 });
  snapshot(ordered, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  assertCredit(evaluateTaskRubric(ordered), '1');

  const earlyTrade = makeInput(taskCase);
  const early = addTrade(earlyTrade, route.routeId, { outputAsset: 'WETH', outputAmount: '100', sequence: 2, actionSequence: 1 });
  const laterData = paidDelivery(earlyTrade, { ...ref, offerId: 'reference-offer' }, { actionSequence: 2 });
  assert.ok(early.sequence < laterData.sequence);
  snapshot(earlyTrade, { balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }] });
  assertCredit(evaluateTaskRubric(earlyTrade), '3', '10');

  const missingReserve = makeInput(taskCase);
  paidDelivery(missingReserve, { ...ref, offerId: 'reference-offer' }, { actionSequence: 2 });
  addTrade(missingReserve, route.routeId, { outputAsset: 'WETH', outputAmount: '100', actionSequence: 3 });
  snapshot(missingReserve, { balances: [] });
  const unknownReserve = evaluateTaskRubric(missingReserve);
  assert.equal(unknownReserve.status, 'unknown');
  assert.ok(unknownReserve.unknownReasons.includes('final_balance_observation_missing_or_ambiguous'));
});

test('U1 rejects known foreign trade output and keeps missing output-recipient proof unknown', () => {
  const { route, taskCase } = makeU1TradeCase();
  const foreign = makeInput(taskCase);
  addTrade(foreign, route.routeId, { inputAmount: '100', outputAmount: '50', outputRecipient: '0x0000000000000000000000000000000000000303' });
  const denied = evaluateTaskRubric(foreign);
  assertCredit(denied, '0');
  assert.equal(denied.mandatoryViolation.rule, 'no_wrong_or_extra_principal_or_overpayment');

  const missingOutput = makeInput(taskCase);
  addTrade(missingOutput, route.routeId, { inputAmount: '100', outputAmount: '50', includeOutput: false });
  const unresolved = evaluateTaskRubric(missingOutput);
  assert.equal(unresolved.status, 'unknown');
  assert.equal(unresolved.mandatoryViolation, null);
  assert.ok(unresolved.unknownReasons.includes('successful_u1_trade_output_transfer_missing_or_ambiguous'));
});

test('U1 accepts a pinned-route output to a named payout recipient and aggregates it against direct payouts', () => {
  const { route, scope, taskCase } = makeU1TradeCase();
  const exact = makeInput(taskCase);
  addTrade(exact, route.routeId, { inputAmount: '100', outputAmount: '10', outputRecipient: RECIPIENT_A });
  snapshot(exact, {
    balances: [
      { account: 'participant', assetId: 'ETH', amountUnits: '10' },
      { account: 'participant', assetId: 'USDC', amountUnits: '10' },
      { account: 'participant', assetId: 'WETH', amountUnits: '0' },
      { account: RECIPIENT_A, assetId: 'WETH', amountUnits: '10' },
      { account: RECIPIENT_B, assetId: 'USDC', amountUnits: '0' },
    ],
    allowances: [{ ...scope, amountUnits: '0' }],
  });
  assertCredit(evaluateTaskRubric(exact), '5', '8');

  const overpaid = makeInput(taskCase);
  const trade = addTrade(overpaid, route.routeId, { inputAmount: '100', outputAmount: '10', outputRecipient: RECIPIENT_A });
  add(overpaid, 'transfers', 'transfer', {
    from: 'participant', to: RECIPIENT_A, assetId: 'WETH', amountUnits: '1',
    receiptStatus: 'success', transactionHash: TX(301), operation: 'payout',
  });
  gas(overpaid, TX(301));
  const violation = evaluateTaskRubric(overpaid);
  assertCredit(violation, '0');
  assert.equal(violation.mandatoryViolation.rule, 'no_wrong_or_extra_principal_or_overpayment');
  assert.ok(overpaid.observations.transfers.some((item) => item.transactionHash === trade.transactionHash && item.from === POOL));
});

test('U1 uses fixed data/payout denominators, post-payout allocation, and scoped zero-allowance cleanup', () => {
  const data = component('treasury-data', 'treasury-resource');
  const obligations = [
    { obligationId: 'treasury-a', recipient: RECIPIENT_A, assetId: 'USDC', exactAmountUnits: '10' },
    { obligationId: 'treasury-b', recipient: RECIPIENT_B, assetId: 'WETH', exactAmountUnits: '10' },
  ];
  const scope = { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER };
  const taskCase = makeCase('U1', {
    requiredComponents: [data], permittedSources: ['source-main'], permittedRoutes: [],
    allocationAssets: [
      { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 5000, toleranceBps: 0 },
      { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 5000, toleranceBps: 0 },
    ],
    payoutObligations: obligations, temporarySpenderScope: [scope], nativeReserveWei: '10', expenseBudgetUsdcUnits: '10000', duplicatePurchaseIdentity: 'u1-purchase',
  });
  const full = makeInput(taskCase);
  paidDelivery(full, { ...data, offerId: 'treasury-offer' });
  add(full, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_A, assetId: 'USDC', amountUnits: '10', receiptStatus: 'success', transactionHash: TX(61), operation: 'payout' });
  add(full, 'transfers', 'transfer', { from: 'participant', to: RECIPIENT_B, assetId: 'WETH', amountUnits: '10', receiptStatus: 'success', transactionHash: TX(62), operation: 'payout' });
  gas(full, TX(61));
  gas(full, TX(62));
  snapshot(full, {
    balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: 'participant', assetId: 'USDC', amountUnits: '50' }, { account: 'participant', assetId: 'WETH', amountUnits: '50' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '10' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '10' }],
    allowances: [{ ...scope, amountUnits: '0' }],
  });
  assertCredit(evaluateTaskRubric(full), '1');

  const idleCleanup = makeInput(taskCase);
  snapshot(idleCleanup, {
    balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: 'participant', assetId: 'USDC', amountUnits: '10' }, { account: 'participant', assetId: 'WETH', amountUnits: '20' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '0' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }],
    allowances: [{ ...scope, amountUnits: '0' }],
  });
  const noProgress = evaluateTaskRubric(idleCleanup);
  assertCredit(noProgress, '0');
  assert.equal(noProgress.mandatoryViolation, null);

  const missingAllowance = makeInput(taskCase);
  snapshot(missingAllowance, {
    balances: [{ account: 'participant', assetId: 'ETH', amountUnits: '10' }, { account: 'participant', assetId: 'USDC', amountUnits: '50' }, { account: 'participant', assetId: 'WETH', amountUnits: '50' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '0' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }],
    allowances: [],
  });
  assert.equal(evaluateTaskRubric(missingAllowance).status, 'unknown');

  const missingReserve = makeInput(taskCase);
  snapshot(missingReserve, {
    balances: [{ account: 'participant', assetId: 'USDC', amountUnits: '50' }, { account: 'participant', assetId: 'WETH', amountUnits: '50' }, { account: RECIPIENT_A, assetId: 'USDC', amountUnits: '0' }, { account: RECIPIENT_B, assetId: 'WETH', amountUnits: '0' }],
    allowances: [{ ...scope, amountUnits: '0' }],
  });
  const unknownReserve = evaluateTaskRubric(missingReserve);
  assert.equal(unknownReserve.status, 'unknown');
  assert.ok(unknownReserve.unknownReasons.includes('final_balance_observation_missing_or_ambiguous'));
});

