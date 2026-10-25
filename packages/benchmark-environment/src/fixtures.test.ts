import assert from 'node:assert/strict';
import test from 'node:test';
import { pinnedFixtureFundingTimestamp } from './fixtures.js';

const source = {
  blockNumber: '0x1234',
  blockHash: `0x${'a'.repeat(64)}`,
  blockTimestamp: '0x64',
};

const forkHead = {
  number: source.blockNumber,
  hash: source.blockHash,
  timestamp: source.blockTimestamp,
};

test('pins fixture funding to exactly one second after the unchanged source fork head', () => {
  assert.equal(pinnedFixtureFundingTimestamp(source, forkHead), 101n);
});

test('rejects a funding timestamp when latest is not the pinned fork head', () => {
  assert.throws(
    () => pinnedFixtureFundingTimestamp(source, { ...forkHead, number: '0x1235' }),
    { message: 'fixture_funding_head_not_pinned' },
  );
  assert.throws(
    () => pinnedFixtureFundingTimestamp(source, { ...forkHead, hash: `0x${'b'.repeat(64)}` }),
    { message: 'fixture_funding_head_not_pinned' },
  );
  assert.throws(
    () => pinnedFixtureFundingTimestamp(source, { ...forkHead, timestamp: '0x65' }),
    { message: 'fixture_funding_head_not_pinned' },
  );
});

test('rejects a timestamp that cannot be passed losslessly to the pinned Anvil JSON-RPC method', () => {
  const tooLargeSource = { ...source, blockTimestamp: '0x20000000000000' };
  assert.throws(
    () => pinnedFixtureFundingTimestamp(tooLargeSource, {
      ...forkHead,
      timestamp: tooLargeSource.blockTimestamp,
    }),
    { message: 'fixture_funding_timestamp_invalid' },
  );
});
