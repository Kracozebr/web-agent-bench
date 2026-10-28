import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  BefTaskExecutor,
  classifyBefTaskActionResponse,
  classifyReadOnlyBefTaskActionResponse,
  classifySplitPayBefTaskActionResponse,
  dispatchSplitPaymentRequest,
  dispatchSplitRetrieveRequest,
  participantToolBody,
  participantToolRequest,
  readOnlyToolResponseMatches,
  safeMeasurementProjection,
  selectedActionMatches,
  type EphemeralX402Signer,
  type PinnedX402Policy,
} from './bef-task-executor.js';
import { recordTaskActionReceipt, TaskActionCommandSchema } from './task-action-service.js';
import type { TaskActionCommand } from './task-action-service.js';

const operationId = 'bef_operation_0123456789';
const txHash = `0x${'a'.repeat(64)}`;
const response = {
  outcome: 'success', operationId,
  receipt: { transactionHash: txHash, status: 'success', gasUsed: '55000', effectiveGasPrice: '1000' },
  transaction: { hash: txHash },
  selectedAction: { kind: 'transfer', amountUnits: '15', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000' },
};

test('classifies a bound participant receipt as observed', () => {
  const result = classifyBefTaskActionResponse({
    status: 200, headerOperationId: operationId, body: response, rawResponseSha256: 'b'.repeat(64), participantToolResponse: response,
  });
  assert.equal(result.status, 'observed');
  assert.equal(result.transactionHash, txHash);
  assert.equal(result.befOperationId, operationId);
  assert.equal(result.participantToolResponse?.receipt, response.receipt);
});

test('accepts the body operation binding without an optional header and rejects contradictions', () => {
  assert.equal(classifyBefTaskActionResponse({
    status: 200, headerOperationId: null, body: response, rawResponseSha256: 'b'.repeat(64), participantToolResponse: response,
  }).status, 'observed');
  assert.equal(classifyBefTaskActionResponse({
    status: 200, headerOperationId: 'different_operation_123', body: response, rawResponseSha256: 'b'.repeat(64),
  }).status, 'unknown');
  const missingBodyOperation = { ...response, operationId: undefined };
  assert.equal(classifyBefTaskActionResponse({
    status: 200, headerOperationId: operationId, body: missingBodyOperation, rawResponseSha256: 'b'.repeat(64), participantToolResponse: missingBodyOperation,
  }).status, 'unknown');
  const mismatch = { ...response, transaction: { hash: `0x${'c'.repeat(64)}` } };
  assert.equal(classifyBefTaskActionResponse({
    status: 200, headerOperationId: operationId, body: mismatch, rawResponseSha256: 'b'.repeat(64), participantToolResponse: mismatch,
  }).status, 'unknown');
  assert.equal(classifyBefTaskActionResponse({
    status: 502, headerOperationId: operationId, body: response, rawResponseSha256: 'b'.repeat(64),
  }).status, 'unknown');
});

test('only explicit pre-broadcast participant errors are rejected', () => {
  assert.equal(classifyBefTaskActionResponse({
    status: 409, headerOperationId: null, body: { error: 'generation_signer_unavailable' }, rawResponseSha256: 'b'.repeat(64),
  }).status, 'rejected_before_execution');
  assert.equal(classifyBefTaskActionResponse({
    status: 409, headerOperationId: null, body: { error: 'generation_or_idempotency_conflict' }, rawResponseSha256: 'b'.repeat(64),
  }).status, 'unknown');
});

test('bounds read-only command selectors to the pinned catalog and offer routes', () => {
  assert.equal(TaskActionCommandSchema.safeParse({ kind: 'inspect_catalog' }).success, true);
  assert.equal(TaskActionCommandSchema.safeParse({ kind: 'inspect_offer', resourceId: 'fixture-resource' }).success, true);
  assert.equal(TaskActionCommandSchema.safeParse({ kind: 'inspect_offer', resourceId: 'fixture-resource', offerId: 'offer-a' }).success, true);
  assert.equal(TaskActionCommandSchema.safeParse({ kind: 'inspect_offer', resourceId: 'fixture-resource', url: 'https://evil.invalid' }).success, false);
  assert.deepEqual(participantToolRequest({ kind: 'inspect_catalog' }), { method: 'GET', path: '/catalog' });
  assert.deepEqual(participantToolRequest({ kind: 'inspect_offer', resourceId: 'fixture-resource', offerId: 'offer-a' }), {
    method: 'GET', path: '/offer?resourceId=fixture-resource',
  });
});

test('observes only structurally pinned read-only catalog and offer results', () => {
  const payment = {
    scheme: 'exact', network: 'base', asset: '0x1111111111111111111111111111111111111111',
    amount: '2500', payTo: '0x2222222222222222222222222222222222222222', transferMethod: 'transferWithAuthorization',
  };
  const offer = { id: 'offer-a', payment };
  const catalogCommand = { kind: 'inspect_catalog' } as const satisfies TaskActionCommand;
  const catalogBody = {
    catalog: [{ resourceId: 'resource-a', resourceSha256: 'a'.repeat(64), contentType: 'application/json',
      schema: 'v1', provenance: { source: 'pinned-fixture' }, offers: [offer] }],
    freeInspection: true, deliveryState: 'not_delivered',
  };
  assert.equal(readOnlyToolResponseMatches(catalogCommand, catalogBody), true);
  assert.equal(classifyReadOnlyBefTaskActionResponse({
    command: catalogCommand, status: 200, headerOperationId: null, body: catalogBody,
    rawResponseSha256: 'b'.repeat(64), participantToolResponse: catalogBody,
  }).status, 'observed');
  assert.equal(classifyReadOnlyBefTaskActionResponse({
    command: catalogCommand, status: 200, headerOperationId: 'not-an-operation-id', body: catalogBody,
    rawResponseSha256: 'b'.repeat(64), participantToolResponse: catalogBody,
  }).status, 'unknown');

  const offerCommand = { kind: 'inspect_offer', resourceId: 'resource-a', offerId: 'offer-a' } as const satisfies TaskActionCommand;
  const offerBody = {
    operationId: '01234567-89ab-4cde-8fab-0123456789ab', resourceId: 'resource-a',
    resourceSha256: 'a'.repeat(64), contentType: 'application/json', payment,
    offers: [offer], freeInspection: true, deliveryState: 'not_delivered',
  };
  assert.equal(readOnlyToolResponseMatches(offerCommand, offerBody), true);
  assert.equal(readOnlyToolResponseMatches({ ...offerCommand, offerId: 'wrong-offer' }, offerBody), false);
  assert.equal(classifyReadOnlyBefTaskActionResponse({
    command: offerCommand, status: 200, headerOperationId: offerBody.operationId, body: offerBody,
    rawResponseSha256: 'c'.repeat(64), participantToolResponse: offerBody,
  }).status, 'observed');
  assert.equal(classifyReadOnlyBefTaskActionResponse({
    command: offerCommand, status: 200, headerOperationId: '01234567-89ab-4cde-8fab-0123456789ac', body: offerBody,
    rawResponseSha256: 'c'.repeat(64), participantToolResponse: offerBody,
  }).status, 'unknown');
});

test('rejects evidence paths that can escape the repository artifact root', async () => {
  await assert.rejects(recordTaskActionReceipt({ db: {} as never }, {
    actionId: '01234567-89ab-4cde-8fab-0123456789ab', status: 'unknown', evidenceHash: 'd'.repeat(64),
    evidencePath: '../private.txt',
  }), (error: unknown) => Boolean(error && typeof error === 'object' && 'code' in error && error.code === 'INVALID_ACTION_RECEIPT'));
});

test('participant POST body excludes route kind and validates selected swap tier', () => {
  const transfer = {
    kind: 'transfer', amountUnits: '15', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000',
  } as const satisfies Exclude<TaskActionCommand, { kind: 'purchase' }>;
  assert.deepEqual(participantToolBody(transfer), {
    amountUnits: '15', recipient: '0x1111111111111111111111111111111111111111', gasLimit: '100000',
  });
  assert.equal(selectedActionMatches(transfer, response.selectedAction), true);
  assert.equal(selectedActionMatches(transfer, { ...response.selectedAction, amountUnits: '16' }), false);

  const reverseSwap = {
    kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH', feeTier: 3000,
    amountInUnits: '2500', amountOutMinimumUnits: '1',
    recipient: '0x2222222222222222222222222222222222222222', gasLimit: '200000',
  } as const satisfies Exclude<TaskActionCommand, { kind: 'purchase' }>;
  const safeSelected = {
    kind: 'swap', route: 'uniswap-v3-exactInputSingle', router: '0x3333333333333333333333333333333333333333',
    inputAssetId: 'USDC', outputAssetId: 'WETH', fee: 3000, tokenIn: '0x4444444444444444444444444444444444444444',
    tokenOut: '0x5555555555555555555555555555555555555555', poolAddress: '0x6666666666666666666666666666666666666666',
    poolCodeHash: 'd'.repeat(64), amountInUnits: '2500', amountOutMinimumUnits: '1',
    recipient: reverseSwap.recipient, gasLimit: '200000',
  };
  assert.equal(selectedActionMatches(reverseSwap, safeSelected), true);
  assert.equal(selectedActionMatches({ ...reverseSwap, feeTier: 500 }, safeSelected), false);
  assert.equal(participantToolBody(reverseSwap).kind, undefined);
});

test('retains the complete allow-listed measurement while removing credential fields', () => {
  const secret = 'ephemeral_run_token_value_never_to_persist_123';
  const measured = {
    ...response,
    receipt: { ...response.receipt, logs: [{ address: '0x1111111111111111111111111111111111111111', data: '0x1234' }], privateKey: 'never-persist' },
    transaction: { ...response.transaction, input: '0x1234', authorization: secret },
    before: { payerNativeWei: '10', poolLiquidity: '20' },
    after: { payerNativeWei: '9', poolLiquidity: '21' },
    effects: { payerNativeWei: '-1' }, fee: { selectedPrincipalUnits: '15' },
    payerBlock: { number: '42', transactions: [{ hash: txHash }] },
    untrustedDiagnostic: 'omit this field',
  };
  const safe = safeMeasurementProjection(measured, secret)!;
  assert.deepEqual((safe.receipt as Record<string, unknown>).logs, measured.receipt.logs);
  assert.equal('privateKey' in (safe.receipt as Record<string, unknown>), false);
  assert.deepEqual(safe.transaction, { hash: txHash, input: '0x1234' });
  assert.equal('untrustedDiagnostic' in safe, false);
  assert.equal(JSON.stringify(safe).includes(secret), false);
});

const readOperationId = '01234567-89ab-4cde-8fab-0123456789ab';
const paymentOperationId = '11234567-89ab-4cde-8fab-0123456789ab';
const paymentHash = `0x${'b'.repeat(64)}`;
const manifestHash = 'a'.repeat(64);
const appHash = 'c'.repeat(64);
const assetAddress = '0x1111111111111111111111111111111111111111';
const payToAddress = '0x2222222222222222222222222222222222222222';
const payerAddress = '0x3333333333333333333333333333333333333333';
const resource = {
  resourceId: 'resource-a', resourceSha256: 'd'.repeat(64), contentType: 'application/json',
  offers: [{ id: 'offer-a', amount: '2500' }],
} as const;
const x402Policy: PinnedX402Policy = {
  manifestSha256: manifestHash,
  scheme: 'exact', network: 'eip155:8453', asset: assetAddress,
  assetTransferMethod: 'eip3009', eip712Domain: { name: 'USD Coin', version: '2' },
  maxTimeoutSeconds: 120,
  sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' },
  localAnvil: {
    identity: 'private-anvil-fork', chainId: 8453, anvilVersion: '0.3.1',
    executionNetwork: 'base', hardFork: 'cancun', forkBlockNumber: '0x123', forkBlockHash: `0x${'e'.repeat(64)}`,
  },
  resources: [resource],
};
const health = {
  boundary: 'benchmark-environment-api' as const,
  manifestSha256: manifestHash, applicationSourceSha256: appHash, envId: 'test-env',
  facilitatorAddress: payToAddress,
  anvil: {
    clientVersion: 'anvil/v0.3.1', chainId: '8453', executionNetwork: 'base', hardFork: 'cancun',
    forkBlockNumber: '291', forkBlockHash: `0x${'e'.repeat(64)}`,
  },
  sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' },
};
const binding = {
  runId: '21234567-89ab-4cde-8fab-0123456789ab', taskIndex: 0, envId: 'test-env',
  generationId: '31234567-89ab-4cde-8fab-0123456789ab', manifestHash,
  applicationSourceHash: appHash, runToken: 'r'.repeat(40), payerAddress,
} as const;
const acceptedTerms = {
  scheme: 'exact', network: 'eip155:8453', asset: assetAddress, amount: '2500',
  payTo: payToAddress, transferMethod: 'eip3009',
};
const splitPayCommand = {
  kind: 'pay', resourceId: resource.resourceId, offerId: 'offer-a',
  offerReadActionId: '41234567-89ab-4cde-8fab-0123456789ab',
} as const satisfies Extract<TaskActionCommand, { kind: 'pay' }>;

function splitPaySigner(): EphemeralX402Signer {
  const required = {
    x402Version: 2,
    resource: { url: 'http://localhost/tools/test-env/pay', mimeType: 'application/json' },
    accepts: [{
      scheme: 'exact', network: 'eip155:8453', asset: assetAddress, payTo: payToAddress,
      amount: '2500', maxTimeoutSeconds: 60,
      extra: { assetTransferMethod: 'eip3009', paymentFlow: 'authorization', name: 'USD Coin', version: '2' },
    }],
  };
  return {
    payerAddress,
    parsePaymentRequired: () => required as never,
    createAuthorization: async () => ({ 'payment-signature': 'x'.repeat(24) }),
    parseSettlement: (headers) => headers['payment-response'] === 'confirmed' ? {
      success: true, transaction: paymentHash, network: 'eip155:8453', payer: payerAddress, amount: '2500',
    } as never : null,
  };
}

function splitPaidBody() {
  return {
    operationId: paymentOperationId, status: 'payment_confirmed',
    payment: {
      transactionHash: paymentHash, receiptStatus: 'success', amount: '2500',
      asset: assetAddress, network: 'eip155:8453', payTo: payToAddress,
    },
    deliveryHandle: paymentOperationId,
  };
}

function challengeResponse() {
  return new Response(JSON.stringify({ operationId: paymentOperationId }), {
    status: 402,
    headers: { 'content-type': 'application/json', 'x-bef-operation-id': paymentOperationId, 'payment-required': 'challenge' },
  });
}

test('split pay sends one challenge and one signed POST to the same pinned pay operation without reading a fresh offer', async () => {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  const result = await dispatchSplitPaymentRequest({
    fetch: async (input, init = {}) => {
      calls.push({ url: new URL(String(input)), init });
      return calls.length === 1 ? challengeResponse() : new Response(JSON.stringify(splitPaidBody()), {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-bef-operation-id': paymentOperationId, 'payment-response': 'confirmed' },
      });
    },
    timeoutMs: 5_000, apiBase: new URL('http://localhost'), binding: { ...binding, x402Signer: splitPaySigner() },
    command: splitPayCommand,
    reference: { kind: 'pay', readHandle: { kind: 'offer', operationId: readOperationId }, acceptedTerms },
    policy: x402Policy,
    selected: { resource, offer: resource.offers[0]! }, health,
    idempotencyKey: 'task-action-501',
  });

  assert.equal(result.status, 'observed');
  assert.deepEqual(calls.map((call) => [call.init.method, call.url.pathname]), [
    ['POST', '/tools/test-env/pay'], ['POST', '/tools/test-env/pay'],
  ]);
  assert.deepEqual(calls.map((call) => (call.init.headers as Record<string, string>)['idempotency-key']), [
    'task-action-501', 'task-action-501',
  ]);
  assert.equal((calls[0]!.init.headers as Record<string, string>)['payment-signature'], undefined);
  assert.equal((calls[1]!.init.headers as Record<string, string>)['payment-signature'], 'x'.repeat(24));
  assert.equal(calls[0]!.init.body, calls[1]!.init.body);
  assert.deepEqual(JSON.parse(String(calls[0]!.init.body)), {
    resourceId: resource.resourceId, offerId: 'offer-a',
    readHandle: { kind: 'offer', operationId: readOperationId }, acceptedTerms,
  });
  assert.equal(calls.some((call) => call.url.pathname.endsWith('/offer')), false);
  assert.equal(result.participantToolResponse?.status, 'payment_confirmed');
  assert.equal('content' in result.participantToolResponse!, false);
});

test('split pay refuses changed inspected terms before contacting BEF', async () => {
  let calls = 0;
  const result = await dispatchSplitPaymentRequest({
    fetch: async () => { calls += 1; return challengeResponse(); },
    timeoutMs: 5_000, apiBase: new URL('http://localhost'), binding: { ...binding, x402Signer: splitPaySigner() },
    command: splitPayCommand,
    reference: { kind: 'pay', readHandle: { kind: 'offer', operationId: readOperationId }, acceptedTerms: { ...acceptedTerms, amount: '2501' } },
    policy: x402Policy,
    selected: { resource, offer: resource.offers[0]! }, health,
    idempotencyKey: 'task-action-502',
  });

  assert.equal(result.status, 'rejected_before_execution');
  assert.equal(calls, 0);
});

test('a lost signed pay response is unknown and is never retried by the split dispatcher', async () => {
  let calls = 0;
  const result = await dispatchSplitPaymentRequest({
    fetch: async () => {
      calls += 1;
      if (calls === 1) return challengeResponse();
      throw new Error('signed reply lost');
    },
    timeoutMs: 5_000, apiBase: new URL('http://localhost'), binding: { ...binding, x402Signer: splitPaySigner() },
    command: splitPayCommand,
    reference: { kind: 'pay', readHandle: { kind: 'offer', operationId: readOperationId }, acceptedTerms },
    policy: x402Policy,
    selected: { resource, offer: resource.offers[0]! }, health,
    idempotencyKey: 'task-action-503',
  });

  assert.equal(result.status, 'unknown');
  assert.equal(calls, 2);
});

test('split pay requires the explicit payment_confirmed response status and exact response fields', () => {
  const common = {
    status: 200, headerOperationId: paymentOperationId, rawResponseSha256: 'f'.repeat(64),
    expectedOperationId: paymentOperationId,
    settlement: { success: true, transaction: paymentHash, network: 'eip155:8453', payer: payerAddress, amount: '2500' },
    payerAddress, network: 'eip155:8453', asset: assetAddress, amount: '2500', payTo: payToAddress,
  };
  const good = splitPaidBody();
  const projection = safeMeasurementProjection(good, binding.runToken)!;
  assert.equal(classifySplitPayBefTaskActionResponse({ ...common, body: good, participantToolResponse: projection }).status, 'observed');
  assert.equal(classifySplitPayBefTaskActionResponse({
    ...common, body: { ...good, status: 'success' }, participantToolResponse: safeMeasurementProjection({ ...good, status: 'success' }, binding.runToken)!,
  }).status, 'unknown');
  assert.equal(classifySplitPayBefTaskActionResponse({
    ...common, body: { ...good, content: { secret: true } }, participantToolResponse: safeMeasurementProjection({ ...good, content: { secret: true } }, binding.runToken)!,
  }).status, 'unknown');
  const invalidStatusProjection = safeMeasurementProjection({ ...good, status: 'success' }, binding.runToken)!;
  assert.equal('status' in invalidStatusProjection, false);
  assert.equal('deliveryHandle' in invalidStatusProjection, false);
});

test('split retrieve needs no signer and exposes bytes only after pinned hash validation', async () => {
  const content = { amount: '13', symbol: 'WETH' };
  const contentBytes = Buffer.from(JSON.stringify(content), 'utf8');
  const contentSha256 = createHash('sha256').update(contentBytes).digest('hex');
  const body = {
    operationId: paymentOperationId, resourceId: resource.resourceId,
    contentType: resource.contentType, contentHash: contentSha256,
    contentBytes: contentBytes.toString('base64'), content,
  };
  const pinnedResource = { ...resource, resourceSha256: contentSha256 };
  const fetch = async (responseBody: Record<string, unknown>) => {
    const calls: Array<{ url: URL; init: RequestInit }> = [];
    const result = await dispatchSplitRetrieveRequest({
      fetch: async (input, init = {}) => {
        calls.push({ url: new URL(String(input)), init });
        return new Response(JSON.stringify(responseBody), {
          status: 200, headers: { 'content-type': 'application/json', 'x-bef-operation-id': paymentOperationId },
        });
      },
      timeoutMs: 5_000, apiBase: new URL('http://localhost'), binding,
      operationId: paymentOperationId, resource: pinnedResource, policy: { ...x402Policy, resources: [pinnedResource] },
      idempotencyKey: 'task-action-504', health,
    });
    return { result, calls };
  };

  const good = await fetch(body);
  assert.equal(good.result.status, 'observed');
  assert.deepEqual(good.result.participantToolResponse?.content, content);
  assert.equal(good.calls.length, 1);
  assert.equal(good.calls[0]!.init.method, 'GET');
  assert.equal(good.calls[0]!.url.pathname, `/tools/test-env/retrieve`);
  assert.equal(good.calls[0]!.url.searchParams.get('operationId'), paymentOperationId);
  assert.equal((good.calls[0]!.init.headers as Record<string, string>)['content-type'], undefined);

  const wrongHash = await fetch({ ...body, contentHash: '0'.repeat(64) });
  assert.equal(wrongHash.result.status, 'unknown');
  assert.equal('content' in (wrongHash.result.participantToolResponse ?? {}), false);
  assert.equal('contentBytes' in (wrongHash.result.participantToolResponse ?? {}), false);
});

test('post-start attach verifies the committed public binding and stores only RAM credentials', async () => {
  const runId = '21234567-89ab-4cde-8fab-0123456789ab';
  const generationId = '31234567-89ab-4cde-8fab-0123456789ab';
  const envId = 'strict-start-env';
  const environmentManifestHash = 'd'.repeat(64);
  const applicationSourceHash = 'e'.repeat(64);
  const caseId = 'synthetic-S1-case';
  const caseHash = 'a'.repeat(64);
  const executionIdentityHash = 'b'.repeat(64);
  const initialStateSha256 = 'c'.repeat(64);
  const preparationId = '41234567-89ab-4cde-8fab-0123456789ab';
  const leaseId = '51234567-89ab-4cde-8fab-0123456789ab';
  const claimId = '61234567-89ab-4cde-8fab-0123456789ab';
  const input = {
    runId, taskIndex: 0, envId, generationId,
    manifestHash: environmentManifestHash, applicationSourceHash,
    runToken: 'R'.repeat(43),
  };
  const contextRow = {
    run_id: runId, run_status: 'running', mode: 'training', task_ids: ['S1'], release_identity: 'synthetic-release',
    run_manifest_hash: 'a'.repeat(64), run_live: true, task_index: 0, task_id: 'S1', task_status: 'active',
    closure_status: 'open', task_live: true, active_task_count: 1, preparation_id: preparationId, lease_id: leaseId,
    preparation_claim_id: claimId, preparation_environment_id: envId, preparation_release_identity: 'synthetic-release',
    preparation_manifest_hash: 'a'.repeat(64), preparation_task_id: 'S1', case_id: caseId, case_hash: caseHash,
    initial_state_sha256: initialStateSha256, execution_identity_hash: executionIdentityHash,
    environment_manifest_sha256: environmentManifestHash, application_source_hash: applicationSourceHash,
    lease_state: 'leased', observation_status: 'ready', observation_generation_id: generationId,
    baseline_state_sha256: initialStateSha256, fixture_evidence: { path: 'fixture.json', sha256: 'f'.repeat(64), boundary: 'actual_tool_http_x402_local_evm_application_store' },
    baseline_evidence: { path: 'baseline.json', sha256: '1'.repeat(64), boundary: 'actual_tool_http_x402_local_evm_application_store' },
    observation_participant_id: null, observation_payer_address: null, registered_generation_id: generationId,
    generation_environment_id: envId, binding_environment_id: envId, binding_generation_id: generationId,
    binding_manifest_hash: environmentManifestHash, binding_application_source_hash: applicationSourceHash,
    binding_participant_id: null, binding_payer_address: null, run_claim_id: claimId, claim_status: 'claimed',
    slot_claim_id: claimId, slot_state: 'running',
  };
  const rows = [
    [contextRow],
    [{ run_id: runId, task_index: 0, env_id: envId, generation_id: generationId,
      manifest_hash: environmentManifestHash, application_source_hash: applicationSourceHash,
      participant_id: null, payer_address: null, created_at: new Date() }],
    [contextRow],
  ];
  const db = { async execute() { return rows.shift() ?? []; } };
  const executor = new BefTaskExecutor({
    db: db as never,
    taskReleaseSource: { async getValidatedReleaseRecord() {
      return { releaseIdentity: 'synthetic-release', manifestHash: 'a'.repeat(64), manifest: { cases: { training: [{
        taskId: 'S1', caseId, caseHash, executionIdentityHash, initialState: { stateSha256: initialStateSha256 },
      }] }, executionIdentity: {
        environmentManifestSha256: environmentManifestHash, x402ServiceSha256: applicationSourceHash,
      } } };
    } } as never,
    participantApiByEnvironment: { [envId]: 'http://localhost:18545' },
    evidenceSink: { async write() { return { path: 'artifacts/runs/no-action.json', sha256: 'f'.repeat(64) }; } },
    fetch: async () => new Response(JSON.stringify({
      status: 'ready', boundary: 'benchmark-environment-api', manifestSha256: environmentManifestHash,
      applicationSourceSha256: applicationSourceHash, environments: [{ envId }],
    }), { status: 200 }),
  });

  await executor.attachStartedSession(input);
  await executor.attachStartedSession(input);
    assert.equal(rows.length, 0, 'an exact RAM replay uses the already-attached session');
  await assert.rejects(executor.attachStartedSession({ ...input, generationId: '41234567-89ab-4cde-8fab-0123456789ab' }),
    /task_action_executor_session_rebind_denied/);
});

test('post-start attach refuses a still-preparing run before checking health or binding', async () => {
  const runId = '51234567-89ab-4cde-8fab-0123456789ab';
  const input = {
    runId, taskIndex: 0, envId: 'strict-start-env', generationId: '61234567-89ab-4cde-8fab-0123456789ab',
    manifestHash: 'd'.repeat(64), applicationSourceHash: 'e'.repeat(64), runToken: 'R'.repeat(43),
  };
  let dbCalls = 0, healthCalls = 0;
  const executor = new BefTaskExecutor({
    db: { async execute() { dbCalls += 1; return [{ id: runId, task_index: 0, status: 'preparing', environment_id: null,
      release_identity: 'synthetic-release', manifest_hash: 'a'.repeat(64) }]; } } as never,
    taskReleaseSource: { async getValidatedReleaseRecord() { throw new Error('must not read release before run starts'); } } as never,
    participantApiByEnvironment: { 'strict-start-env': 'http://localhost:18545' },
    evidenceSink: { async write() { return { path: 'artifacts/runs/no-action.json', sha256: 'f'.repeat(64) }; } },
    fetch: async () => { healthCalls += 1; return new Response('{}', { status: 200 }); },
  });

  await assert.rejects(executor.attachStartedSession(input), /task_action_executor_run_environment_mismatch/);
  assert.equal(dbCalls, 1);
  assert.equal(healthCalls, 0);
});
