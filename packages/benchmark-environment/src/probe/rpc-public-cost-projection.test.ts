import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { keccak256, toBytes } from 'viem';
import { EvidenceWriter } from './evidence.js';
import { ReadOnlyRpcEvidence } from './rpc.js';

const transactionHash = `0x${'1'.repeat(64)}`;
const blockHash = `0x${'2'.repeat(64)}`;
const parentHash = `0x${'3'.repeat(64)}`;
const payer = `0x${'4'.repeat(40)}`;
const destination = `0x${'5'.repeat(40)}`;
const wrongDestination = `0x${'a'.repeat(40)}`;
const spender = `0x${'6'.repeat(40)}`;
const sentinel = `0x${'9'.repeat(64)}`;
const selectedHash = `0x${'8'.repeat(64)}`;
const mismatchedHash = `0x${'7'.repeat(64)}`;
const selectedInput = `0x095ea7b3${'0'.repeat(24)}${spender.slice(2)}${'0'.repeat(63)}1`;
const mismatchedInput = `0x095ea7b3${'0'.repeat(24)}${spender.slice(2)}${'0'.repeat(63)}2`;
const transferWithAuthorizationInput = `${keccak256(toBytes('transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)')).slice(0, 10)}${'0'.repeat(9 * 64)}`;

test('SC-008 transaction and full-block evidence persists only fixed public cost fields', async () => {
  const manifestSha256 = 'a'.repeat(64);
  const url = 'http://127.0.0.1:8545';
  const evidenceDirectory = await mkdtemp(join(tmpdir(), 'bef-sc008-rpc-projection-'));
  const evidence = new EvidenceWriter(evidenceDirectory);
  await evidence.initialize();
  const rpc = new ReadOnlyRpcEvidence(evidence);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/healthz')) {
      return new Response(JSON.stringify({
        status: 'ok', boundary: 'local-chain-readonly-proxy', envId: 'bef-sc008-projection', manifestSha256,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const request = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
    const requestedHash = request.params[0];
    const isSelected = requestedHash === selectedHash;
    const isMismatched = requestedHash === mismatchedHash;
    const tx = {
      hash: isSelected ? selectedHash : isMismatched ? mismatchedHash : transactionHash,
      from: payer, to: destination, value: '0x0', nonce: '0x1',
      type: '0x2', chainId: '0x2105', gas: '0x5208', maxFeePerGas: '0x100', maxPriorityFeePerGas: '0x2',
      blockHash, blockNumber: '0x10', transactionIndex: '0x0',
      input: isSelected ? selectedInput : isMismatched ? mismatchedInput : sentinel,
      r: sentinel, s: sentinel, v: sentinel,
      authorization: { signature: sentinel, nonce: sentinel },
    };
    const malformedAllowedField = request.params[0] === `0x${'6'.repeat(64)}`;
    const malformedBlock = request.params[0] === '0x11';
    const result = request.method === 'eth_getTransactionByHash'
      ? { ...tx, ...(malformedAllowedField ? { maxFeePerGas: { input: sentinel } } : {}) }
      : {
        number: malformedBlock ? '0x11' : '0x10', hash: malformedBlock ? `0x${'7'.repeat(64)}` : blockHash,
        parentHash, baseFeePerGas: malformedBlock ? { input: sentinel } : '0x80',
        transactions: [{ ...tx, hash: transactionHash, from: malformedBlock ? { input: sentinel } : payer, input: sentinel, r: sentinel, s: sentinel, v: sentinel }],
      };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  try {
    await rpc.bindLocalEndpoint({ url, environmentId: 'bef-sc008-projection', manifestSha256, label: 'test-binding' });
    const txResult = await rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [transactionHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc008-public-transaction',
    });
    assert.equal(txResult.result.hash, transactionHash);
    assert.equal(txResult.result.from, payer);
    for (const field of ['input', 'r', 's', 'v', 'authorization']) assert.equal(Object.hasOwn(txResult.result, field), false);

    const malformedTx = await rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [`0x${'6'.repeat(64)}`], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc008-malformed-public-transaction',
    });
    assert.equal(Object.hasOwn(malformedTx.result, 'maxFeePerGas'), false);

    await assert.rejects(() => rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [selectedHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc007-x402-calldata-selected-transaction',
      selectedExecutionTransaction: {
        environmentId: 'bef-sc008-projection', operationId: 'operation-a', variantId: 'successful_transaction',
        kind: 'approve', transactionHash: selectedHash, expectedFrom: payer, expectedTo: destination,
        expectedValueWei: '0', expectedChainId: '8453', expectedNonce: '1', expectedGas: '21000',
        expectedInput: transferWithAuthorizationInput,
      },
    }), { message: 'probe_rpc_selected_execution_context_invalid' });

    const selectedResult = await rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [selectedHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc007-selected-transaction',
      selectedExecutionTransaction: {
        environmentId: 'bef-sc008-projection', operationId: 'operation-a', variantId: 'successful_transaction',
        kind: 'approve', transactionHash: selectedHash, expectedFrom: payer, expectedTo: destination,
        expectedValueWei: '0', expectedChainId: '8453', expectedNonce: '1', expectedGas: '21000', expectedInput: selectedInput,
      },
    });
    assert.equal(selectedResult.result.input, selectedInput);
    for (const field of ['r', 's', 'v', 'authorization']) assert.equal(Object.hasOwn(selectedResult.result, field), false);

    await assert.rejects(() => rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [mismatchedHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc007-mismatched-selected-transaction',
      selectedExecutionTransaction: {
        environmentId: 'bef-sc008-projection', operationId: 'operation-a', variantId: 'successful_transaction',
        kind: 'approve', transactionHash: mismatchedHash, expectedFrom: payer, expectedTo: destination,
        expectedValueWei: '0', expectedChainId: '8453', expectedNonce: '1', expectedGas: '21000', expectedInput: selectedInput,
      },
    }), { message: 'probe_rpc_selected_execution_transaction_binding_invalid' });

    await assert.rejects(() => rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [selectedHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc007-wrong-destination-selected-transaction',
      selectedExecutionTransaction: {
        environmentId: 'bef-sc008-projection', operationId: 'operation-a', variantId: 'successful_transaction',
        kind: 'approve', transactionHash: selectedHash, expectedFrom: payer, expectedTo: wrongDestination,
        expectedValueWei: '0', expectedChainId: '8453', expectedNonce: '1', expectedGas: '21000', expectedInput: selectedInput,
      },
    }), { message: 'probe_rpc_selected_execution_transaction_binding_invalid' });

    await assert.rejects(() => rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getTransactionByHash', params: [selectedHash], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc007-wrong-context-selected-transaction',
      selectedExecutionTransaction: {
        environmentId: 'bef-sc008-projection', operationId: 'operation-b', variantId: 'successful_transaction',
        kind: 'approve', transactionHash: selectedHash, expectedFrom: payer, expectedTo: destination,
        expectedValueWei: '0', expectedChainId: '8453', expectedNonce: '1', expectedGas: '21000', expectedInput: selectedInput,
      },
    }), { message: 'probe_rpc_selected_execution_context_invalid' });

    const blockResult = await rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getBlockByNumber', params: ['0x10', true], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc008-public-cost-block',
    });
    const transactions = blockResult.result.transactions as Array<Record<string, unknown>>;
    assert.deepEqual(transactions, [{ hash: transactionHash, from: payer }]);

    const malformedBlockResult = await rpc.call<Record<string, unknown>>({
      url, endpointBoundary: 'local-chain-readonly-proxy', environmentId: 'bef-sc008-projection',
      method: 'eth_getBlockByNumber', params: ['0x11', true], operationId: 'operation-a',
      variantId: 'successful_transaction', label: 'sc008-malformed-public-cost-block',
    });
    assert.equal(Object.hasOwn(malformedBlockResult.result, 'baseFeePerGas'), false);
    assert.deepEqual(malformedBlockResult.result.transactions, [{ hash: transactionHash }]);

    const relevantArtifacts = evidence.artifacts.filter((artifact) =>
      artifact.path.includes('sc008-public-transaction') || artifact.path.includes('sc008-public-cost-block')
      || artifact.path.includes('sc008-malformed-public'));
    assert.equal(relevantArtifacts.length, 4);
    for (const artifact of relevantArtifacts) {
      const serialized = await readFile(join(evidenceDirectory, artifact.path), 'utf8');
      assert.equal(serialized.includes(sentinel), false);
      assert.equal(serialized.includes('authorization'), false);
      for (const field of ['input', 'r', 's', 'v']) assert.equal(serialized.includes(`"${field}"`), false);
      const observation = JSON.parse(serialized) as Record<string, unknown>;
      assert.ok(observation.resultProjection);
    }
    const selectedArtifact = evidence.artifacts.find((artifact) => artifact.path.includes('sc007-selected-transaction'));
    assert.ok(selectedArtifact);
    const selectedSerialized = await readFile(join(evidenceDirectory, selectedArtifact.path), 'utf8');
    assert.ok(selectedSerialized.includes(selectedInput));
    assert.equal(selectedSerialized.includes(sentinel), false);
    for (const field of ['r', 's', 'v', 'authorization']) assert.equal(selectedSerialized.includes(`"${field}"`), false);
    assert.equal(evidence.artifacts.some((artifact) => artifact.path.includes('sc007-mismatched-selected-transaction')), false);
    assert.equal(evidence.artifacts.some((artifact) => artifact.path.includes('sc007-wrong-destination-selected-transaction')), false);
    assert.equal(evidence.artifacts.some((artifact) => artifact.path.includes('sc007-wrong-context-selected-transaction')), false);
    assert.equal(evidence.artifacts.some((artifact) => artifact.path.includes('sc007-x402-calldata-selected-transaction')), false);
  } finally {
    globalThis.fetch = originalFetch;
    await rm(evidenceDirectory, { recursive: true, force: true });
  }
});
