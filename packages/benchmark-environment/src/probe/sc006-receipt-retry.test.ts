import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { EvidenceWriter } from './evidence.js';
import { ReadOnlyRpcEvidence, RpcReadOnlyBoundaryMethodDeniedError } from './rpc.js';
import { retrySc006ReceiptRead } from './runner.js';

const transactionHash = `0x${'1'.repeat(64)}`;
const receipt = {
  transactionHash,
  status: '0x1',
  blockNumber: '0x1',
  blockHash: `0x${'2'.repeat(64)}`,
  from: `0x${'3'.repeat(40)}`,
  to: `0x${'4'.repeat(40)}`,
  logs: [],
};

test('SC006 retries only the recorded local read-boundary denial for the same hash and keeps every attempt', async () => {
  const manifestSha256 = 'a'.repeat(64);
  const seenRequests: Array<{ method: unknown; params: unknown }> = [];
  let receiptAttempts = 0;
  const url = 'http://127.0.0.1:8545';
  const evidenceDirectory = await mkdtemp(join(tmpdir(), 'bef-sc006-receipt-retry-'));
  const evidence = new EvidenceWriter(evidenceDirectory);
  await evidence.initialize();
  const rpc = new ReadOnlyRpcEvidence(evidence);
  const originalFetch = globalThis.fetch;
  let returnNonExactDenial = false;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/healthz')) {
      return new Response(JSON.stringify({
        status: 'ok', boundary: 'local-chain-readonly-proxy', envId: 'bef-sc006-retry', manifestSha256,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const body = JSON.parse(String(init?.body)) as { method: unknown; params: unknown };
    seenRequests.push({ method: body.method, params: body.params });
    receiptAttempts += 1;
    const payload = returnNonExactDenial
      ? {
        jsonrpc: '2.0', id: 1,
        error: { code: -32601, message: 'A different method denial' },
      }
      : receiptAttempts < 3
      ? {
        jsonrpc: '2.0', id: 1,
        error: { code: -32601, message: 'Method is not permitted by the read-only boundary' },
      }
      : { jsonrpc: '2.0', id: 1, result: receipt };
    return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;

  try {
    await rpc.bindLocalEndpoint({
      url,
      environmentId: 'bef-sc006-retry',
      manifestSha256,
      label: 'test-endpoint-binding',
    });
    const observedReceipt = await retrySc006ReceiptRead((attempt) => rpc.receipt({
      url,
      boundary: 'local-chain-readonly-proxy',
      transactionHash,
      operationId: 'operation-1',
      variantId: 'missing_receipt',
      label: `sc006-missing_receipt-independent-receipt-${attempt}`,
    }), async () => {});

    assert.equal(observedReceipt.transactionHash, transactionHash);
    assert.deepEqual(seenRequests, [1, 2, 3].map(() => ({
      method: 'eth_getTransactionReceipt',
      params: [transactionHash],
    })));
    const attemptArtifacts = evidence.artifacts.filter((artifact) => /^rpc\/\d{4}-sc006-missing_receipt-independent-receipt-/.test(artifact.path));
    assert.equal(attemptArtifacts.length, 3);
    const attempts = await Promise.all(attemptArtifacts.map(async (artifact) =>
      JSON.parse(await readFile(join(evidenceDirectory, artifact.path), 'utf8')) as Record<string, any>));
    assert.deepEqual(attempts.slice(0, 2).map((attempt) => attempt.result.error), [
      { code: -32601, message: 'Method is not permitted by the read-only boundary' },
      { code: -32601, message: 'Method is not permitted by the read-only boundary' },
    ]);
    assert.equal(attempts[2]!.result.transactionHash, transactionHash);

    returnNonExactDenial = true;
    let rejectedAttempts = 0;
    await assert.rejects(
      retrySc006ReceiptRead((attempt) => {
        rejectedAttempts += 1;
        return rpc.receipt({
          url,
          boundary: 'local-chain-readonly-proxy',
          transactionHash,
          operationId: 'operation-1',
          variantId: 'missing_receipt',
          label: `sc006-nonexact-denial-${attempt}`,
        });
      }, async () => {}),
      (error: unknown) => error instanceof Error && error.message === 'probe_rpc_call_failed',
    );
    assert.equal(rejectedAttempts, 1);
    const nonExactArtifact = evidence.artifacts.find((artifact) => artifact.path.includes('sc006-nonexact-denial-1'));
    assert.ok(nonExactArtifact);
    const nonExactObservation = JSON.parse(await readFile(join(evidenceDirectory, nonExactArtifact.path), 'utf8')) as Record<string, any>;
    assert.deepEqual(nonExactObservation.result.error, { code: -32601, message: 'A different method denial' });
  } finally {
    globalThis.fetch = originalFetch;
    await rm(evidenceDirectory, { recursive: true, force: true });
  }
});

test('SC006 does not retry generic RPC failures or denials from another boundary or method', async () => {
  let calls = 0;
  const unrelatedErrors = [
    new Error('probe_rpc_call_failed'),
    new RpcReadOnlyBoundaryMethodDeniedError('source-readonly-proxy', 'eth_getTransactionReceipt'),
    new RpcReadOnlyBoundaryMethodDeniedError('local-chain-readonly-proxy', 'eth_call'),
  ];
  for (const error of unrelatedErrors) {
    calls = 0;
    await assert.rejects(
      retrySc006ReceiptRead(async () => {
        calls += 1;
        throw error;
      }, async () => {}),
      error,
    );
    assert.equal(calls, 1);
  }
});

test('SC006 caps same-boundary denial retries at 24 attempts', async () => {
  const denial = new RpcReadOnlyBoundaryMethodDeniedError('local-chain-readonly-proxy', 'eth_getTransactionReceipt');
  let calls = 0;
  await assert.rejects(
    retrySc006ReceiptRead(async () => {
      calls += 1;
      throw denial;
    }, async () => {}),
    denial,
  );
  assert.equal(calls, 24);
});
