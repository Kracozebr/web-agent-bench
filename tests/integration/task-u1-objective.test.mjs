/** Synthetic arithmetic contracts; no U1 execution or release acceptance. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { planU1LocalAllocation, u1UsdcShareWithin } from '../../packages/benchmark-environment/dist/probe/task-u1-objective.js';

const input = { initialUsdcUnits: '100000000', initialNativeWei: '10000000000000000000',
  paidServiceUnits: '225000', payoutUnits: ['100000', '200000'], swapInputUsdcUnits: '1500000',
  minimumNativeOutputWei: '560000000000000', quotedNativeOutputWei: '625000000000000',
  maximumParticipantGasWei: '10000000000000', ethUsdcRateNumerator: '2400000000', ethUsdcRateDenominator: '1000000000000000000' };

test('local U1 plan pins an initially unsolved native allocation before actions', () => {
  const plan = planU1LocalAllocation(input);
  assert.equal(plan.initiallySolved, false);
  assert.equal(plan.projectedBounds.finalUsdcUnits, '97975000');
  assert.equal(plan.allocationAssets[0].targetShareBps, 40);
  assert.equal(plan.allocationAssets[1].assetId, 'ETH');
  assert.equal(plan.requiresExactInputPublicQuote, true);
  input.payoutUnits[0] = '99999';
  assert.equal(plan.plannedInput.payoutUnits[0], '100000');
  input.payoutUnits[0] = '100000';
});

test('local U1 planning rejects trivial starts, missing payout sets and infeasible bounds', () => {
  assert.throws(() => planU1LocalAllocation({ ...input, initialUsdcUnits: '98000000' }), /initially_solved/);
  assert.throws(() => planU1LocalAllocation({ ...input, payoutUnits: ['100000'] }), /payout_set_too_small/);
  assert.throws(() => planU1LocalAllocation({ ...input, swapInputUsdcUnits: '100000' }), /outside_target/);
  assert.throws(() => planU1LocalAllocation({ ...input, maximumParticipantGasWei: input.initialNativeWei }), /bounds_invalid/);
  assert.throws(() => planU1LocalAllocation({ ...input, minimumNativeOutputWei: '700000000000000' }), /bounds_invalid/);
});

test('U1 allocation band uses exact rational boundaries including one-unit negatives', () => {
  const band = { nativeWei: 959n, rateNumerator: 1n, rateDenominator: 1n, targetShareBps: 400, toleranceBps: 10 };
  assert.equal(u1UsdcShareWithin({ ...band, usdcUnits: 41n }), true);
  assert.equal(u1UsdcShareWithin({ ...band, usdcUnits: 42n }), false);
  assert.equal(u1UsdcShareWithin({ ...band, usdcUnits: 38n }), false);
  assert.throws(() => u1UsdcShareWithin({ ...band, usdcUnits: 41n, rateDenominator: 0n }), /invalid_allocation_band/);
});
