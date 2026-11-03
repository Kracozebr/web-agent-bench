import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import { createPublicClient, http, TimeoutError } from 'viem';
import { inPostminePhase, observeOriginalHashWithinBudget, PostmineObservationError, postmineFailureCode } from './selected-observation-retry.js';

test('real SDK HTTP availability failure retries only the original readonly RPC, with the same shared budget and no write method', async () => {
  const methods: string[] = [], remaining: number[] = [];
  const server = createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body); methods.push(rpc.method);
    if (methods.length === 1) { response.writeHead(503).end('PRIVATE_PROVIDER_MESSAGE'); return; }
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: '0x2a' }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const result = await observeOriginalHashWithinBudget({ deadline: Date.now() + 3000, read: (ms, signal) => {
      remaining.push(ms);
      const observer = createPublicClient({ transport: http(url, { retryCount: 0, fetchOptions: { signal } }) });
      return inPostminePhase('blocks', () => observer.getBlockNumber({ cacheTime: 0 }));
    } });
    assert.equal(result, 42n); assert.deepEqual(methods, ['eth_blockNumber', 'eth_blockNumber']);
    assert(remaining[1]! < remaining[0]! - 90, 'the second read consumes the original time budget');
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('binding contradiction, failed effects and malformed measurement do not retry as availability', async () => {
  for (const error of [new Error('original_transaction_binding_mismatch'),
    new PostmineObservationError('measurement', new TimeoutError({ body: {}, url: 'http://unused.invalid' })),
    new PostmineObservationError('effects', new Error('PRIVATE_CANARY'))]) {
    let calls = 0;
    await assert.rejects(observeOriginalHashWithinBudget({ deadline: Date.now() + 1000, read: async () => { calls++; throw error; } }), candidate => candidate === error);
    assert.equal(calls, 1); assert(!String(postmineFailureCode(error)).includes('PRIVATE_CANARY'));
  }
  let calls = 0;
  const effectsValid = await observeOriginalHashWithinBudget({ deadline: Date.now() + 1000, read: async () => { calls++; return false; } });
  assert.equal(effectsValid, false); assert.equal(calls, 1);
});

test('availability retries at most once and exhausted reads preserve a finite phase without provider text', async () => {
  let calls = 0, clock = 0;
  const error = new PostmineObservationError('poststate', new TimeoutError({ body: {}, url: 'http://PRIVATE_CANARY.invalid' }));
  await assert.rejects(observeOriginalHashWithinBudget({ deadline: 1000, now: () => clock, sleep: async ms => { clock += ms; },
    read: async () => { calls++; throw error; } }), candidate => candidate === error);
  assert.equal(calls, 2); assert.equal(postmineFailureCode(error), 'postmine_poststate_observation_unavailable');
  calls = 0;
  await assert.rejects(observeOriginalHashWithinBudget({ deadline: 100, now: () => 0,
    read: async () => { calls++; throw error; } }), candidate => candidate === error);
  assert.equal(calls, 1);
});

test('absolute original deadline aborts a hanging postmine read and prevents further observer calls', async () => {
  let calls = 0, signalObserved: AbortSignal | undefined;
  const started = Date.now();
  await assert.rejects(observeOriginalHashWithinBudget({ deadline: started + 35, read: async (_remaining, signal) => {
    calls++; signalObserved = signal;
    return new Promise<never>((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('read_aborted')), { once: true }));
  } }), /postmine_observation_budget_exhausted/);
  assert.equal(calls, 1); assert.equal(signalObserved?.aborted, true); assert(Date.now() - started < 1000);
  await assert.rejects(observeOriginalHashWithinBudget({ deadline: Date.now() - 1, read: async () => { calls++; return true; } }), /postmine_observation_budget_exhausted/);
  assert.equal(calls, 1);
});

test('already consumed trial time is not reset for either attempt and every phase has only a finite code', async () => {
  let clock = 850, calls = 0; const remaining: number[] = [];
  const error = new PostmineObservationError('transaction', new TimeoutError({ body: {}, url: 'http://unused.invalid' }));
  const result = await observeOriginalHashWithinBudget({ deadline: 1000, now: () => clock, sleep: async ms => { clock += ms; },
    read: async ms => { remaining.push(ms); if (++calls === 1) throw error; return true; } });
  assert.equal(result, true); assert.deepEqual(remaining, [150, 50]);
  for (const phase of ['receipt', 'transaction', 'blocks', 'poststate', 'measurement', 'effects'] as const) {
    try { await inPostminePhase(phase, () => { throw new Error('PROVIDER_SECRET_CANARY'); }); }
    catch (failure) {
      assert(failure instanceof PostmineObservationError); failure.message = 'PROVIDER_SECRET_CANARY';
      assert.equal(postmineFailureCode(failure), `postmine_${phase}_observation_unavailable`);
    }
  }
});

test('original budget abort reaches an actual pending SDK HTTP read, not only the outer promise', async () => {
  let calls = 0, closed = false;
  const server = createServer(async (request, response) => {
    calls++; for await (const _chunk of request) { /* Consume the real SDK request, leave its response pending. */ }
    response.on('close', () => { closed = true; });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await assert.rejects(observeOriginalHashWithinBudget({ deadline: Date.now() + 100, read: (_ms, signal) => {
      const observer = createPublicClient({ transport: http(url, { timeout: 15_000, retryCount: 0, fetchOptions: { signal } }) });
      return inPostminePhase('poststate', () => observer.getBlockNumber({ cacheTime: 0 }));
    } }), /postmine_observation_budget_exhausted/);
    for (let i = 0; i < 20 && !closed; i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(calls, 1); assert.equal(closed, true, 'the SDK transport must close its original pending read');
  } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('strict persistence failures retain only exact registered finite codes, never arbitrary messages', () => {
  for (const code of ['execution_persistence_measurement_invalid', 'execution_persistence_measurement_action_invalid',
    'execution_persistence_measurement_action_binding_conflict', 'execution_persistence_measurement_action_receipt_conflict',
    'execution_persistence_terminal_binding_conflict']) assert.equal(postmineFailureCode(new Error(code)), code);
  for (const message of ['execution_persistence_PRIVATE_TOKEN', 'execution_persistence_measurement_action_invalid https://PRIVATE.invalid', 'PRIVATE_PROVIDER_MESSAGE']) {
    assert.equal(postmineFailureCode(new Error(message)), null);
  }
});
