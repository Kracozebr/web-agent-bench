import assert from 'node:assert/strict';
import test from 'node:test';
import {brlAuthorizationEvidence} from './benchmark-run-lifecycle-launch-probe.mjs';
import {assertSecretFree} from './evidence.mjs';
test('authorization rejection observations remain recordable without authorization material', () => {
  const owner = {status:401, body:{error:{code:'UNAUTHORIZED'}}, authorizationHeaderPresent:false};
  const foreign = {status:404, body:{error:{code:'RUN_INTENT_NOT_FOUND'}}, authorizationHeaderPresent:true};
  const evidence = brlAuthorizationEvidence(owner,foreign);
  assert.doesNotThrow(() => assertSecretFree(evidence));
  assert.equal(evidence.authorizationChecks.ownerSessionAsAgent.status,401);
  assert.equal(evidence.authorizationChecks.foreignAgent.status,404);
  assert.throws(() => brlAuthorizationEvidence({headers:{authorization:'unsafe-fixture-value'}},foreign),/prohibited secret-bearing field/);
});