import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import type { ProbeContext } from './runner.js';
import type { RuntimeManifest } from '../manifest.js';
import { aggregateReferenceCosts, validateReferenceCostRow, projectH1DifficultyV2Candidate,
  h2InitialRecipientBalancesMatchPolicy, h2RecipientDeltasMatchObligations,
  type ValidatedReferenceCost } from './task-reference-h1h2-drivers.js';

const address = `0x${'1'.repeat(40)}`;
const tx1 = `0x${'a'.repeat(64)}`;
const tx2 = `0x${'b'.repeat(64)}`;
const manifestHash = 'c'.repeat(64);
const manifest = {
  feePolicy: {
    baseFeeWei: '1', priorityFeeWei: '2', ethUsdcRateNumerator: '10', ethUsdcRateDenominator: '3',
    rounding: 'floor-to-6-decimal-usdc-units', baseL1Fee: 'unmodelled', principalSeparateFromExpense: true,
  },
} as unknown as RuntimeManifest;

test('v2 H1 cannot count a legacy combined-purchase capture as seven separate public actions', async () => {
  const root = fileURLToPath(new URL('../../../../', import.meta.url));
  const bytes = await readFile(new URL('../../../../infrastructure/benchmark-environment/manifest.json', import.meta.url));
  const ctx = { runtime: { root, manifest: JSON.parse(bytes.toString('utf8')),
    manifestSha256: createHash('sha256').update(bytes).digest('hex') } } as unknown as ProbeContext;
  await assert.rejects(projectH1DifficultyV2Candidate(ctx, { catalogCapture: { purchases: [] },
    deliveryProjections: [], elapsedMs: 0 }, { profileId: 'bts-task-difficulty-v2', mode: 'ranked' }),
  /task_reference_h1_split_payment_trace_not_captured/);
});

test('H2 v2 preserves a measured nonzero recipient baseline while legacy still requires zero', () => {
  const recipient = `0x${'1'.repeat(40)}`;
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], { [recipient]: '90000' }, false), true);
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], { [recipient]: '90000' }, true), false);
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], { [recipient]: '0' }, true), true);
});

test('H2 baseline validation rejects missing or noncanonical balances and checks exact deltas from measured units', () => {
  const recipient = `0x${'1'.repeat(40)}`;
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], {}, false), false);
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], { [recipient]: '00' }, false), false);
  assert.equal(h2InitialRecipientBalancesMatchPolicy([recipient], { [recipient]: '-0' }, false), false);
  const obligations = [{ recipient, amountUnits: '125000' }];
  assert.equal(h2RecipientDeltasMatchObligations(obligations, { [recipient]: '90000' }, { [recipient]: '215000' }), true);
  assert.equal(h2RecipientDeltasMatchObligations(obligations, { [recipient]: '90000' }, { [recipient]: '214999' }), false);
  assert.equal(h2RecipientDeltasMatchObligations(obligations, {}, { [recipient]: '215000' }), false);
});

function validatedCost(overrides: Partial<ValidatedReferenceCost> = {}): ValidatedReferenceCost {
  return {
    operationId: 'operation-1', transactionHash: tx1, payerAddress: address,
    payerRole: 'participant', gasUsed: '1', effectiveGasPriceWei: '1', gasCostWei: '1',
    modeledGasFeeUsdcUnitsPerReceipt: '3', feeRateNumerator: '10', feeRateDenominator: '3',
    receiptStatus: 'success', baseL1FeeStatus: 'unmodelled',
    ...overrides,
  };
}

function costRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    operation_id: 'operation-1', transaction_hash: tx1, payer_address: address, payer_role: 'participant',
    receipt_status: 'success', transaction_from: address, receipt_from: address,
    gas_used: '2', effective_gas_price_wei: '3', gas_cost_wei: '6', modeled_gas_fee_usdc_units: '20',
    fee_rate_numerator: '10', fee_rate_denominator: '3',
    fee_policy_snapshot: {
      baseFeeWei: '1', priorityFeeWei: '2', ethUsdcRateNumerator: '10', ethUsdcRateDenominator: '3',
      rounding: 'floor-to-6-decimal-usdc-units', baseL1Fee: 'unmodelled', principalSeparateFromExpense: true,
    },
    manifest_sha256: manifestHash, base_l1_fee_status: 'unmodelled',
    ...overrides,
  };
}

test('aggregate reference cost applies the rational valuation once after summing participant gas wei', () => {
  const result = aggregateReferenceCosts([
    validatedCost({ gasCostWei: '1', modeledGasFeeUsdcUnitsPerReceipt: '3' }),
    validatedCost({ operationId: 'operation-2', transactionHash: tx2, gasCostWei: '2', modeledGasFeeUsdcUnitsPerReceipt: '6' }),
    validatedCost({ operationId: 'operation-3', transactionHash: `0x${'d'.repeat(64)}`, payerRole: 'facilitator', gasCostWei: '9', modeledGasFeeUsdcUnitsPerReceipt: '30' }),
  ]);
  assert.equal(result.participantGasWei, 3n);
  assert.equal(result.participantAggregateGasUsdcUnits, 10n);
  assert.equal(result.participantReceiptRoundedGasUsdcUnits, 9n);
  assert.equal(result.facilitatorGasWei, 9n);
  assert.equal(result.facilitatorAggregateGasUsdcUnits, 30n);
});

test('aggregate reference cost rejects duplicate transaction hashes case-insensitively', () => {
  assert.throws(() => aggregateReferenceCosts([
    validatedCost(),
    validatedCost({ operationId: 'operation-2', transactionHash: tx1.toUpperCase() }),
  ]), /task_reference_cost_duplicate_receipt/);
});

test('aggregate reference cost rejects duplicate operation identities', () => {
  assert.throws(() => aggregateReferenceCosts([
    validatedCost(),
    validatedCost({ transactionHash: tx2 }),
  ]), /task_reference_cost_duplicate_receipt/);
});

test('cost row validation binds the exact payer, fee snapshot, and manifest', () => {
  const expected = { operationId: 'operation-1', transactionHash: tx1, payerRole: 'participant' as const, payerAddress: address, manifestSha256: manifestHash };
  const valid = validateReferenceCostRow(costRow(), manifest, expected);
  const feePolicySnapshot = costRow().fee_policy_snapshot as Record<string, unknown>;
  assert.equal(valid.gasCostWei, '6');
  assert.equal(valid.modeledGasFeeUsdcUnitsPerReceipt, '20');
  assert.throws(() => validateReferenceCostRow(costRow({ payer_address: 'not-an-address' }), manifest, expected), /task_reference_cost_row_binding_mismatch/);
  assert.throws(() => validateReferenceCostRow(costRow({ fee_policy_snapshot: { ...feePolicySnapshot, baseFeeWei: '99' } }), manifest, expected), /task_reference_cost_row_binding_mismatch/);
  assert.throws(() => validateReferenceCostRow(costRow({ manifest_sha256: 'd'.repeat(64) }), manifest, expected), /task_reference_cost_row_binding_mismatch/);
});
