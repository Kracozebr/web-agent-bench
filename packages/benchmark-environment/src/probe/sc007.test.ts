import assert from 'node:assert/strict';
import test from 'node:test';
import { runSc007Variant, SC007_VARIANTS, slippageRevertGasUsedBelowLimit } from './sc007.js';
import type { ProbeContext } from './runner.js';

test('SC007 reset sends an empty JSON object to the admin endpoint', async () => {
  const resetRequests: Array<{ body?: unknown }> = [];
  const context = {
    scenarioId: 'BEF-SC-007',
    runtime: {
      manifest: { guardrails: { maxTrialSeconds: 120 } },
      manifestSha256: '0'.repeat(64),
      appSourceSha256: '1'.repeat(64),
    },
    env: {
      envId: 'bef-test',
      apiBaseUrl: 'http://127.0.0.1:3000',
      adminKey: 'test-admin-key',
      localRpcUrl: 'http://127.0.0.1:8545',
    },
    capability: {
      reset: { supported: true, route: 'POST /internal/admin/environments/{envId}/reset' },
    },
    transport: {
      setDeadlineAt: () => undefined,
      request: async (request: { body?: unknown }) => {
        resetRequests.push(request);
        return { status: 400, body: { error: 'reset_request_must_be_empty' } };
      },
    },
    rpc: {
      setDeadlineAt: () => undefined,
      bindLocalEndpoint: async () => undefined,
    },
    database: { setDeadlineAt: () => undefined },
  } as unknown as ProbeContext;

  await assert.rejects(
    runSc007Variant(context, SC007_VARIANTS[0]),
    /probe_sc007_reset_failed_400/,
  );
  assert.deepEqual(resetRequests[0]?.body, {});
});

test('SC007 slippage revert gas check parses RPC hex but rejects missing or malformed gas quantities', () => {
  assert.equal(slippageRevertGasUsedBelowLimit('0x1d257', '1200000'), true);
  assert.equal(slippageRevertGasUsedBelowLimit('0x124f80', '1200000'), false);
  for (const missingOrMalformed of [undefined, null, '', '119383', '0x', '0x01', '0xgg']) {
    assert.throws(() => slippageRevertGasUsedBelowLimit(missingOrMalformed, '1200000'), /probe_sc007_invalid_slippage_revert_gas_used/);
  }
  assert.throws(() => slippageRevertGasUsedBelowLimit('0x1d257', '0x124f80'), /probe_sc007_invalid_slippage_revert_gas_limit/);
});
