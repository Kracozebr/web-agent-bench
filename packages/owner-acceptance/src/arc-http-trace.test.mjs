import assert from 'node:assert/strict';
import test from 'node:test';
import { createArcTracingFetch } from './arc-http-trace.mjs';

test('tracing returns an open MCP SSE response before EOF and retains its actual first event', async () => {
  const rpc = { jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18' } };
  const source = new Response(new ReadableStream({ start(controller) {
    controller.enqueue(new TextEncoder().encode('event: message\ndata: ' + JSON.stringify(rpc) + '\n\n'));
  } }), { headers: { 'content-type': 'text/event-stream' } });
  const records = [];
  const trace = createArcTracingFetch({ fetchImpl: async () => source, onRecord: (record) => records.push(structuredClone(record)) });
  const response = await trace.fetch('http://127.0.0.1:3000/api/agent/mcp', { method: 'POST' });
  assert.equal(response, source);
  const reader = response.body.getReader();
  assert.match(new TextDecoder().decode((await reader.read()).value), /event: message/);
  await trace.settle();
  assert.deepEqual(records.at(-1).body, rpc);
  assert.equal(records.at(-1).bodyCaptureStatus, 'complete_sse_event');
  await reader.cancel();
});

test('tracing preserves JSON denial status/body and bounds stalled SSE observation', async () => {
  const records = [];
  const trace = createArcTracingFetch({ timeoutMs: 25, onRecord: (record) => records.push(structuredClone(record)),
    fetchImpl: async (url) => url.endsWith('/denied') ? Response.json({ error: { code: 'UNSUPPORTED_MCP_CLIENT_PROFILE' } }, { status: 400 })
      : new Response(new ReadableStream({ start() {} }), { headers: { 'content-type': 'text/event-stream' } }) });
  await trace.fetch('http://127.0.0.1/denied'); await trace.settle();
  assert.equal(records.at(-1).status, 400);
  assert.equal(records.at(-1).body.error.code, 'UNSUPPORTED_MCP_CLIENT_PROFILE');
  const stalled = await trace.fetch('http://127.0.0.1/stalled');
  const keepAlive = setTimeout(() => {}, 100);
  await trace.settle(); clearTimeout(keepAlive);
  assert.equal(records.at(-1).bodyCaptureStatus, 'incomplete_timeout');
  await stalled.body.cancel();
});
