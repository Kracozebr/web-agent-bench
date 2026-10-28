import assert from 'node:assert/strict';
import test from 'node:test';
const { issuedTaskConditions } = await import('../../packages/owner-identity/dist/task-issuance.js');

// Projection contracts only: these fixtures do not establish real case solvability.
test('task issuance: transfer instructions exclude sealed initial-state baselines', () => {
  const task = { taskId: 'S1', objective: { tokenAssetId: 'USDC', sender: 'participant',
    recipient: '0x1111111111111111111111111111111111111111', exactPrincipalUnits: '100000',
    nativeReserveWei: '100', unrelatedEffectBaselineSha256: 'sealed-baseline' }, referencePath: 'sealed-reference' };
  assert.deepEqual(issuedTaskConditions(task), { tokenAssetId: 'USDC', sender: 'participant',
    recipient: task.objective.recipient, exactPrincipalUnits: '100000', nativeReserveWei: '100' });
});

test('task issuance: read-only answer discovery does not issue the expected payment answer', () => {
  const task = { taskId: 'S2', objective: { resourceId: 'dataset', offerId: 'offer',
    requiredAnswerFields: ['amount', 'recipient'], completePaymentRequirements: { amountUnits: 'sealed-answer' } } };
  assert.deepEqual(issuedTaskConditions(task), { resourceId: 'dataset', offerId: 'offer', requiredAnswerFields: ['amount', 'recipient'] });
  assert.equal(JSON.stringify(issuedTaskConditions(task)).includes('sealed-answer'), false);
});

test('task issuance: scoped selection criteria exclude the sealed catalog', () => {
  const task = { taskId: 'S3', objective: { required: { requiredDataType: 'prices' }, catalog: [{ offerId: 'sealed-choice' }] } };
  assert.deepEqual(issuedTaskConditions(task), { required: { requiredDataType: 'prices' } });
});

test('task issuance: composite conditions preserve fixed sets without sharing sealed object references', () => {
  const task = { taskId: 'U1', objective: { requiredComponents: [{ componentId: 'a', resourceId: 'resource', sourceIds: ['source'], validator: { requiredField: 'disclosed-criterion' } }],
    permittedSources: ['source'], permittedRoutes: [], allocationAssets: [], payoutObligations: [{ obligationId: 'b' }], temporarySpenderScope: [],
    nativeReserveWei: '100', expenseBudgetUsdcUnits: '100' },
    initialStateEvidence: 'sealed-initial', referencePath: 'sealed-reference' };
  const issued = issuedTaskConditions(task);
  assert.deepEqual(issued.requiredComponents[0].validator, { requiredField: 'disclosed-criterion' });
  issued.requiredComponents[0].componentId = 'changed';
  assert.equal(task.objective.requiredComponents[0].componentId, 'a');
  assert.equal(JSON.stringify(issued).includes('sealed-'), false);
});

test('task issuance: paid reference instructions disclose the rule while excluding the actual reference value and path', () => {
  const task = { taskId: 'H3', objective: {
    referenceComponent: { componentId: 'reference', resourceId: 'reference-data', sourceIds: ['source'], validator: { predicate: 'disclosed-criterion' } },
    routeObjective: { referenceField: 'routeCode', allowedRouteIds: ['route'], expectedRouteByValue: [{ value: 'code', routeId: 'route' }] },
    inputAssetId: 'USDC', exactInputUnits: '100', permittedRoutes: [], minimumOutputUnits: '1', nativeReserveWei: '100', combinedExpenseBudgetUsdcUnits: '200',
  }, referencePath: { payload: 'sealed-actual-reference-value' } };
  const issued = issuedTaskConditions(task);
  assert.equal(JSON.stringify(issued).includes('sealed-'), false);
  assert.equal(issued.routeObjective.referenceField, 'routeCode');
  assert.deepEqual(issued.routeObjective.expectedRouteByValue, task.objective.routeObjective.expectedRouteByValue);
});

test('task issuance: paid component constraints are disclosed without raw delivery or reference evidence', () => {
  const component = { componentId: 'part', resourceId: 'data', sourceIds: ['source'], validator: { predicate: 'disclosed-criterion' } };
  for (const task of [
    { taskId: 'M1', objective: { component, paymentRequirements: { amountUnits: '100' }, expenseBudgetUsdcUnits: '10' }, referencePath: 'sealed-path' },
    { taskId: 'H1', objective: { requiredComponents: [component], permittedSources: ['source'], expenseBudgetUsdcUnits: '10' } },
  ]) assert.equal(JSON.stringify(issuedTaskConditions(task)).includes('sealed-'), false);
});

test('split-payment issuance retains M1 constraints while terms come from the scoped offer tool', () => {
  const task = { taskId: 'M1', objective: {
    component: { componentId: 'part', resourceId: 'data', sourceIds: ['source'], validator: { predicate: 'criterion' } },
    paymentRequirements: { scheme: 'exact', network: 'eip155:8453', assetId: 'USDC', recipient: 'test-payee',
      offerId: 'selected-offer', amountUnits: '125000', authFields: [{ name: 'version', value: '2' }] },
    expenseBudgetUsdcUnits: '250000',
  } };
  const issued = issuedTaskConditions(task, 'separate_payment_delivery_v2');
  assert.equal(issued.component.resourceId, 'data');
  assert.deepEqual(issued.paymentScope, { scheme: 'exact', network: 'eip155:8453', assetId: 'USDC',
    recipient: 'test-payee', offerId: 'selected-offer', termsSource: 'inspect_offer_or_catalog' });
  assert.equal(issued.expenseBudgetUsdcUnits, '250000');
  assert.equal('paymentRequirements' in issued, false);
  assert.equal('amountUnits' in issued.paymentScope, false);
  assert.equal(issuedTaskConditions(task).paymentRequirements.amountUnits, '125000');
});
