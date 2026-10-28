import assert from 'node:assert/strict';
import test from 'node:test';
import { publicQuoteAmountMatches } from './task-native-capture.js';

test('training exact quote is bound to the requested 200000 USDC principal', () => {
  const response = { requestedAmountInUnits: '200000', quote: { amountInUnits: '200000' } };
  assert.equal(publicQuoteAmountMatches(response, '200000'), true);
  assert.equal(publicQuoteAmountMatches(response, '100000'), false);
});

test('training exact quote rejects mismatched top-level and nested amounts', () => {
  assert.equal(publicQuoteAmountMatches({ requestedAmountInUnits: '200000', quote: { amountInUnits: '100000' } }, '200000'), false);
  assert.equal(publicQuoteAmountMatches({ requestedAmountInUnits: '100000', quote: { amountInUnits: '200000' } }, '200000'), false);
  assert.equal(publicQuoteAmountMatches({ requestedAmountInUnits: '200000', quote: { amountInUnits: '200000' } }, '0'), false);
});
