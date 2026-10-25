import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { Sc006ReceiptReadFaults } from './sc006-receipt-fault.js';

test('receipt fault returns one scoped HTTP 503, binds the first hash, then forwards the real read', async () => {
  let forwarded = 0;
  const rpc = createServer((_request, response) => {
    forwarded += 1;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":1,"result":{"transactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111","status":"0x1"}}');
  });
  rpc.listen(0, '127.0.0.1');
  await once(rpc, 'listening');
  const address = rpc.address();
  assert.ok(address && typeof address !== 'string');
  const target = `http://127.0.0.1:${address.port}`;
  const transactionHash = `0x${'1'.repeat(64)}`;
  const scope = { envId: 'bef-a', generationId: 'generation-1', operationId: 'operation-1' };
  const faults = new Sc006ReceiptReadFaults();
  faults.arm(scope, 5_000);
  faults.recordBroadcast(scope, transactionHash);
  const init = {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [transactionHash] }),
  };
  const read = (activeScope: typeof scope) => async () => {
    const injected = faults.intercept(activeScope, init.body);
    return injected ?? fetch(target, init);
  };
  try {
    const first = await read(scope)();
    assert.equal(first.status, 503);
    assert.equal(forwarded, 0);
    assert.deepEqual(faults.status(scope.operationId), {
      ...scope, armed: true, applied: true, transactionHash, faultedReads: 1,
      broadcastHashes: [transactionHash],
      lastFaultAt: faults.status(scope.operationId)?.lastFaultAt, restored: false,
    });
    const unrelated = await read({ ...scope, operationId: 'operation-2' })();
    assert.equal(unrelated.status, 200);
    const second = await read(scope)();
    assert.equal(second.status, 200);
    assert.equal(forwarded, 2);
    const restored = faults.restore(scope.operationId, scope.generationId);
    assert.equal(restored?.restored, true);
    assert.equal(restored?.faultedReads, 1);
  } finally {
    await new Promise<void>((resolve, reject) => rpc.close((error) => error ? reject(error) : resolve()));
  }
});
