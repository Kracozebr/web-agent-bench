import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  convertEthWeiToUsdcUnits,
  convertWethWeiToUsdcUnits,
  measureAggregateGasUsdcUnits,
  measureDexFee,
  resolveH3FeeTier,
  resolveH3InputUnits,
  resolveM4InputUnits,
  validateH3SettlementBeforeTrade,
  validateH3SettlementChronology,
} from './task-v2-reverse-swap-capture.js';

async function difficultyProfile(): Promise<Record<string, unknown>> {
  const bytes = await readFile(resolve(process.cwd(), 'infrastructure/owner-identity/task-difficulty-profile-v2.json'));
  return JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
}

test('M4 and H3 inputs come from the pinned v2 candidate profile and retain their counted action plans', async () => {
  const profile = await difficultyProfile();
  assert.equal(resolveM4InputUnits(profile, 'ranked'), '100000000000000');
  assert.equal(resolveM4InputUnits(profile, 'training'), '200000000000000');
  assert.equal(resolveH3InputUnits(profile), '100000000000000');
});

test('H3 route selection follows only the authenticated delivered route code mapping', () => {
  assert.equal(resolveH3FeeTier('baseline'), 500);
  assert.equal(resolveH3FeeTier('alternative'), 3000);
  assert.throws(() => resolveH3FeeTier('unlisted'), /task_v2_reverse_h3_delivered_route_code_not_permitted/);
});

test('H3 settlement chronology uses the verified chain receipt, not the pay response body', () => {
  const transactionHash = `0x${'a'.repeat(64)}`;
  const settlementReceipt = {
    blockNumber: '123', blockHash: `0x${'b'.repeat(64)}`, status: '0x1', transactionHash,
  };
  assert.equal(validateH3SettlementBeforeTrade(settlementReceipt, transactionHash, '123'), '123');
  assert.equal(validateH3SettlementChronology(settlementReceipt, transactionHash, '123', '124'), '123');
  assert.throws(() => validateH3SettlementBeforeTrade(settlementReceipt, transactionHash, '122'),
    /task_v2_reverse_h3_paid_receipt_before_trade_invalid/);
  assert.throws(() => validateH3SettlementChronology(settlementReceipt, transactionHash, '123', '123'),
    /task_v2_reverse_h3_paid_reference_to_wrap_chronology_invalid/);
  assert.throws(() => validateH3SettlementChronology({ ...settlementReceipt, status: '0x0' }, transactionHash, '123', '124'),
    /task_v2_reverse_h3_paid_receipt_before_trade_invalid/);
  assert.throws(() => validateH3SettlementChronology(settlementReceipt, `0x${'c'.repeat(64)}`, '123', '124'),
    /task_v2_reverse_h3_paid_receipt_before_trade_invalid/);
});

test('WETH DEX fee is measured in WETH wei before fixed-rational conversion to USDC units', () => {
  const fee = measureDexFee('100000000000000', 3000, '2400000000', '1000000000000000000');
  assert.deepEqual(fee, { feeWethWei: '300000000000', feeUsdcUnits: '720' });
  assert.equal(convertWethWeiToUsdcUnits(fee.feeWethWei, '2400000000', '1000000000000000000'), '720');
});

test('participant gas is aggregated in ETH wei and converted once using the manifest rational', () => {
  const gasCostWei = ['1000000000000000', '2000000000000000', '3000000000000000'];
  assert.equal(measureAggregateGasUsdcUnits(gasCostWei, '2400000000', '1000000000000000000'), '14400000');
  assert.equal(convertEthWeiToUsdcUnits('6000000000000000', '2400000000', '1000000000000000000'), '14400000');
});
