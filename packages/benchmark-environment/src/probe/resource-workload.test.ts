import assert from 'node:assert/strict';
import test from 'node:test';
import {
  fenceOutcome,
  readResponseMatchesGeneration,
  sanitizeFenceDatabaseSnapshot,
  validateResourceWorkloadMarker,
} from './resource-workload.js';

const marker = (schemaVersion: string, phase: string) => ({
  schemaVersion,
  phase,
  envId: 'bef-env-a',
  generationId: '5f21eeab-e3be-4bd8-9c1d-29d669b9c2fd',
  participantId: 'participant-a',
  payerAddress: '0x1111111111111111111111111111111111111111',
  manifestSha256: 'a'.repeat(64),
  applicationSourceSha256: 'b'.repeat(64),
  probeSourceSha256: 'c'.repeat(64),
});

test('resource workload accepts an active-generation fence target for the guardrail phase', () => {
  const input = marker('bef-resource-workload-fence-target/v1', 'guardrail_exceeded');
  assert.deepEqual(validateResourceWorkloadMarker(input), input);
});

test('resource workload keeps marker phases scoped to their exact schema', () => {
  for (const phase of ['cold', 'warm']) {
    assert.equal(
      validateResourceWorkloadMarker(marker('bef-resource-workload-fence-target/v1', phase)).phase,
      phase,
    );
  }
  assert.throws(
    () => validateResourceWorkloadMarker(marker('bef-resource-workload-ready/v1', 'cold')),
    /resource_workload_ready_marker_invalid/,
  );
  assert.throws(
    () => validateResourceWorkloadMarker(marker('bef-resource-workload-fence-target/v1', 'unexpected')),
    /resource_workload_ready_marker_invalid/,
  );
});

test('fence report snapshots redact paid authorization and signature digest without mutating comparisons', () => {
  const paidSnapshot = () => ({
    x402Observations: [{
      safe_request: {
        paymentPayload: {
          payload: {
            authorization: {
              from: '0x1111111111111111111111111111111111111111',
              to: '0x2222222222222222222222222222222222222222',
              value: '123',
              validAfter: '1',
              validBefore: '2',
              nonce: 'sensitive-payment-nonce',
            },
          },
          signatureSha256: 'd'.repeat(64),
        },
      },
    }],
  });
  const databaseBefore = paidSnapshot();
  const databaseAfter = paidSnapshot();
  const reportBefore = sanitizeFenceDatabaseSnapshot(databaseBefore) as typeof databaseBefore;
  const reportAfter = sanitizeFenceDatabaseSnapshot(databaseAfter) as typeof databaseAfter;

  for (const snapshot of [reportBefore, reportAfter]) {
    const paymentPayload = snapshot.x402Observations[0]!.safe_request.paymentPayload;
    assert.equal(paymentPayload.payload.authorization, '[REDACTED]');
    assert.equal(paymentPayload.signatureSha256, '[REDACTED]');
    assert.doesNotMatch(JSON.stringify(snapshot), /sensitive-payment-nonce|d{64}/);
  }
  assert.equal(databaseBefore.x402Observations[0]!.safe_request.paymentPayload.payload.authorization.nonce, 'sensitive-payment-nonce');
  assert.equal(databaseAfter.x402Observations[0]!.safe_request.paymentPayload.signatureSha256, 'd'.repeat(64));
});

test('guardrail balance reads accept the current scoped snapshot object with decimal string fields', () => {
  const session = {
    envId: 'bef-env-a',
    generationId: '5f21eeab-e3be-4bd8-9c1d-29d669b9c2fd',
    payerAddress: '0x35B22DaBB9504082C56568F4Bd3C054D824472Fb',
  } as const;
  const response = {
    boundary: 'local-chain-readonly-proxy',
    envId: 'bef-env-a',
    generationId: session.generationId,
    payer: session.payerAddress.toLowerCase(),
    balances: {
      blockNumber: '52982197',
      payerNativeWei: '10000000000000000000',
      payerWethUnits: '0',
      payerUsdcUnits: '100000000',
      recipientWethUnits: '0',
      recipientUsdcUnits: '100000000',
      wethRouterAllowance: '0',
      usdcRouterAllowance: '0',
      poolWethUnits: '2583319483055206054090',
      poolUsdcUnits: '2491594720540',
      poolLiquidity: '1018126055295016476',
      poolSqrtPriceX96: '3875630849719270719639802',
    },
  };
  assert.equal(readResponseMatchesGeneration(response, session), true);
  assert.equal(readResponseMatchesGeneration({ ...response, balances: [] }, session), false);
  assert.equal(readResponseMatchesGeneration({ ...response, balances: { ...response.balances, payerUsdcUnits: 100 } }, session), false);
  assert.equal(readResponseMatchesGeneration({ ...response, balances: { ...response.balances, payerUsdcUnits: '-1' } }, session), false);
  assert.equal(readResponseMatchesGeneration({ ...response, balances: { ...response.balances, extra: '0' } }, session), false);
  assert.equal(readResponseMatchesGeneration({ ...response, payer: '0x0000000000000000000000000000000000000001' }, session), false);
});

const validFence = {
  fenceHttpStatus: 200,
  responseStatus: 'fenced',
  responseEnvId: 'bef-env-a',
  expectedEnvId: 'bef-env-a',
  responseGenerationId: '5f21eeab-e3be-4bd8-9c1d-29d669b9c2fd',
  generationId: '5f21eeab-e3be-4bd8-9c1d-29d669b9c2fd',
  responseChainState: 'not_touched',
  identityMatchesBeforeFence: true,
  rowsUnchanged: true,
  generationFenced: true,
  chainUnchanged: true,
  returnedCountsMatch: true,
  returnedStatusesMatch: true,
};

test('protective fence succeeds with prior effects without claiming a zero-effect guardrail proof', () => {
  assert.equal(fenceOutcome({
    ...validFence,
    purpose: 'protective_only',
    persistedEffectsUnchangedSinceReadiness: null,
    protectedStateUnchangedSinceReadiness: null,
    guardrailGenerationHadNoEffects: null,
  }), 'protected');
  assert.equal(fenceOutcome({
    ...validFence,
    purpose: 'protective_only',
    persistedEffectsUnchangedSinceReadiness: null,
    protectedStateUnchangedSinceReadiness: null,
    guardrailGenerationHadNoEffects: null,
    generationFenced: false,
  }), 'failed');
});

test('readonly guardrail fence still requires readiness baselines and no prior effects', () => {
  assert.equal(fenceOutcome({
    ...validFence,
    purpose: 'readonly_guardrail',
    persistedEffectsUnchangedSinceReadiness: true,
    protectedStateUnchangedSinceReadiness: true,
    guardrailGenerationHadNoEffects: true,
  }), 'captured');
  assert.equal(fenceOutcome({
    ...validFence,
    purpose: 'readonly_guardrail',
    persistedEffectsUnchangedSinceReadiness: true,
    protectedStateUnchangedSinceReadiness: true,
    guardrailGenerationHadNoEffects: false,
  }), 'failed');
});

test('protective fence cannot carry guardrail readiness claims', () => {
  assert.equal(fenceOutcome({
    ...validFence,
    purpose: 'protective_only',
    persistedEffectsUnchangedSinceReadiness: true,
    protectedStateUnchangedSinceReadiness: true,
    guardrailGenerationHadNoEffects: true,
  }), 'failed');
});
