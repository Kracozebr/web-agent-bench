import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
const { projectRouteDelivery } = await import('../../packages/benchmark-environment/dist/probe/task-route-reference.js');

// Contract fixtures only; actual paid-reference-before-trade evidence remains required.
const routes = [{ value: 'primary', routeId: 'uniswap-v3-500' }, { value: 'alternative', routeId: 'uniswap-v3-3000' }];
function delivery(code = 'alternative') {
  const content = { resourceId: 'brief', content: { routeCode: code } };
  const bytes = Buffer.from(JSON.stringify(content));
  const digest = createHash('sha256').update(bytes).digest('hex');
  return { expectedResourceId: 'brief', expectedContentHash: digest, provenanceId: 'synthetic-benchmark-fixture', routes,
    envelope: { resourceId: 'brief', contentType: 'application/json', contentHash: digest, contentBytes: bytes.toString('base64'), content } };
}

test('paid route selection derives the code from verified bytes while public conditions disclose all mappings', () => {
  const input = delivery();
  input.envelope.routeCode = 'primary'; // An unverified outer label has no authority.
  const result = projectRouteDelivery(input);
  assert.equal(result.selectedRouteId, 'uniswap-v3-3000');
  assert.equal(result.projection.routeCode, 'alternative');
  assert.deepEqual(result.routeObjective.expectedRouteByValue, routes);
  assert.deepEqual(result.component.validator.requiredFields.at(-1), { name: 'routeCode', type: 'string', enumValues: ['primary', 'alternative'] });
  assert.equal(result.component.validator.predicates.some((predicate) => predicate.field === 'routeCode'), false,
    'public conditions must not pin the private actual route value');
  result.routeObjective.expectedRouteByValue[0].routeId = 'changed';
  assert.equal(routes[0].routeId, 'uniswap-v3-500');
});

test('route projection refuses a forged paid field, unknown code, or trivial/ambiguous mapping', () => {
  const changed = delivery();
  changed.envelope.content.content.routeCode = 'primary';
  assert.throws(() => projectRouteDelivery(changed), /content_mismatch/);
  const hashMismatch = delivery();
  hashMismatch.envelope.contentBytes = Buffer.from('changed').toString('base64');
  assert.throws(() => projectRouteDelivery(hashMismatch), /hash_mismatch/);
  assert.throws(() => projectRouteDelivery(delivery('unrecognized')), /paid_code_invalid/);
  assert.throws(() => projectRouteDelivery({ ...delivery(), routes: [routes[0]] }), /mapping_invalid/);
  assert.throws(() => projectRouteDelivery({ ...delivery(), routes: [routes[0], { ...routes[0], routeId: 'another' }] }), /mapping_invalid/);
  assert.throws(() => projectRouteDelivery({ ...delivery(), routes: [routes[0], { value: 'alternative', routeId: routes[0].routeId }] }), /mapping_invalid/);
});
