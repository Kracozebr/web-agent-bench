import { createHash } from 'node:crypto';

// AICODE-NOTE: Observing an MCP SSE response must never wait for stream EOF before
// returning its original response to the client. Keep the fork bounded and separate.
export function createArcTracingFetch({ fetchImpl = fetch, onRecord, timeoutMs = 3000, maxBytes = 2 * 1024 * 1024 }) {
  const pending = new Set();
  async function capture(response, record) {
    const reader = response.clone().body?.getReader();
    if (!reader) { record.body = null; record.bodyCaptureStatus = 'complete_empty'; return; }
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('trace_timeout'), { code: 'trace_timeout' })), timeoutMs);
      timer.unref?.();
    });
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const next = await Promise.race([reader.read(), timeout]);
        if (next.value) { size += next.value.byteLength; if (size > maxBytes) throw new Error('trace_bound'); chunks.push(Buffer.from(next.value)); }
        const text = Buffer.concat(chunks).toString('utf8');
        if (record.contentType.includes('text/event-stream')) {
          const blocks = text.replaceAll('\r\n', '\n').split('\n\n');
          for (const block of blocks.slice(0, -1)) {
            const data = block.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trimStart()).join('\n');
            if (!data) continue;
            try { record.body = JSON.parse(data); record.bodyCaptureStatus = 'complete_sse_event'; return; } catch { /* Wait for a complete JSON-RPC message. */ }
          }
        }
        if (next.done) {
          try { record.body = text ? JSON.parse(text) : null; record.bodyCaptureStatus = 'complete_json'; }
          catch { record.body = { format: 'unparsed', bytes: size, sha256: createHash('sha256').update(Buffer.concat(chunks)).digest('hex') };
            record.bodyCaptureStatus = 'unparsed'; }
          return;
        }
      }
    } catch (error) { record.bodyCaptureStatus = error?.code === 'trace_timeout' ? 'incomplete_timeout' : 'incomplete_bound_or_stream_error'; }
    finally { clearTimeout(timer); void reader.cancel().catch(() => undefined); }
  }
  return {
    async fetch(url, init) {
      const startedAt = new Date().toISOString();
      const response = await fetchImpl(url, init);
      const record = { method: init?.method ?? (url instanceof Request ? url.method : 'GET'),
        path: new URL(url instanceof Request ? url.url : url).pathname, status: response.status,
        startedAt, headersObservedAt: new Date().toISOString(), contentType: response.headers.get('content-type') ?? '',
        bodyCaptureStatus: 'pending' };
      onRecord(record);
      const job = capture(response, record).finally(() => {
        record.finishedAt = new Date().toISOString(); pending.delete(job); onRecord(record);
      });
      pending.add(job);
      return response;
    },
    async settle() { await Promise.allSettled([...pending]); },
  };
}
