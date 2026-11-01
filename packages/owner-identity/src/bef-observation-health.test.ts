import assert from 'node:assert/strict';
import test from 'node:test';
import { observationHealthMatches } from './bef-observation-health.js';

const expected = { environmentId: 'bef-env-a', manifestSha256: 'a'.repeat(64), applicationSourceSha256: 'b'.repeat(64) };
const base = { boundary: 'benchmark-environment-api', envId: expected.environmentId,
  manifestSha256: expected.manifestSha256, applicationSourceSha256: expected.applicationSourceSha256 };
const complete = { ...base, facilitatorAddress: `0x${'1'.repeat(40)}`,
  anvil: { clientVersion: 'anvil/v1.4.4', chainId: '31337', executionNetwork: 'private-anvil',
    hardFork: 'prague', forkBlockNumber: '123', forkBlockHash: `0x${'2'.repeat(64)}` },
  sdkVersions: { core: '2.0.0', evm: '2.0.0', viem: '2.0.0' } };

test('inspection health accepts omitted, base and complete executor metadata with matching identity', () => {
  for (const value of [undefined, base, complete]) assert.equal(observationHealthMatches(value, expected), true);
});

test('inspection health rejects changed identity, unknown fields and malformed optional producer metadata', () => {
  for (const value of [null, [], {}, { ...complete, envId: 'bef-env-b' },
    { ...complete, manifestSha256: 'c'.repeat(64) }, { ...complete, applicationSourceSha256: 'c'.repeat(64) },
    { ...complete, boundary: 'other' }, { ...complete, transactionHash: 'unexpected' },
    { ...complete, facilitatorAddress: 'invalid' }, { ...complete, facilitatorAddress: undefined },
    { ...complete, anvil: { ...complete.anvil, chainId: 31337 } },
    { ...complete, anvil: { ...complete.anvil, secret: 'unexpected' } },
    { ...complete, anvil: null }, { ...complete, sdkVersions: { core: '2', evm: '2' } },
    { ...complete, sdkVersions: { ...complete.sdkVersions, viem: 2 } },
    { ...complete, sdkVersions: { ...complete.sdkVersions, secret: 'unexpected' } }]) {
    assert.equal(observationHealthMatches(value, expected), false);
  }
});

test('modern observation health carries a distinct public payee without replacing the gas signer', () => {
  const modern={...complete,paymentRecipient:`0x${'3'.repeat(40)}`};
  assert.notEqual(modern.paymentRecipient,modern.facilitatorAddress);
  assert.equal(observationHealthMatches(modern,expected),true);
  assert.equal(observationHealthMatches(complete,expected),true);
  for(const paymentRecipient of [undefined,null,'',false,123,'invalid',`0x${'0'.repeat(40)}`]) {
    assert.equal(observationHealthMatches({...modern,paymentRecipient},expected),false);
  }
  assert.equal(observationHealthMatches({...modern,facilitatorAddress:'invalid'},expected),false);
  assert.equal(observationHealthMatches({...modern,paymentRecipientProof:true},expected),false);
});
