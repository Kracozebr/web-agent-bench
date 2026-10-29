import assert from 'node:assert/strict';
import test from 'node:test';
import { quoteUnits } from './beta-combined-restore-cases.mjs';

test('queued restore fixture reads the actual run-launch quote sentence without changing six-decimal units', () => {
  assert.equal(quoteUnits('Server quote for this selection: 0.2 USDC. The intent pins this value and rejects a stale release or changed quote.'), 200000n);
  assert.equal(quoteUnits('0.000001 USDC'), 1n);
  for (const value of ['unavailable USDC', '0.0000001 USDC', '-1 USDC', '1 ETH', '1 USDCx']) {
    assert.throws(() => quoteUnits(value), /combined_quote_display_invalid/);
  }
});
