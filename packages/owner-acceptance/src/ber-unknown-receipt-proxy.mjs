import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TX = /^0x[0-9a-f]{64}$/i;
const READS = new Set(['eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getTransactionByHash',
  'eth_getTransactionReceipt','eth_call','eth_getBalance','eth_getCode','eth_getLogs','eth_getTransactionCount']);

/** Acceptance-only observer fault. It never changes a chain receipt or intercepts participant actions. */
export async function startBerUnknownReceiptProxy({ upstreamOrigin }) {
  const upstream = new URL(upstreamOrigin);
  if (upstream.protocol !== 'http:' || !['127.0.0.1','localhost','host.docker.internal'].includes(upstream.hostname) ||
      upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname !== '/') {
    throw new Error('ber_receipt_proxy_upstream_invalid');
  }
  let mode = 'pass', predicate = async () => null;
  let forwardedRequests = 0, rejectedRequests = 0;
  const records = new Map(), intervals = [];
  const server = createServer(async (request, response) => {
    try {
      if (request.method !== 'POST' || request.url !== '/') throw new Error('read_only_rpc_required');
      const chunks = []; let size = 0;
      for await (const bytes of request) {
        size += bytes.length; if (size > 256 * 1024) throw new Error('request_too_large'); chunks.push(bytes);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const calls = Array.isArray(body) ? body : [body];
      if (calls.length < 1 || calls.length > 64 || calls.some(call => !call || call.jsonrpc !== '2.0' ||
          !READS.has(call.method) || !Array.isArray(call.params))) throw new Error('read_only_rpc_required');
      const raw = await fetch(upstream, { method:'POST', headers:{'content-type':'application/json'},
        body:JSON.stringify(body), signal:AbortSignal.timeout(20_000) });
      if (!raw.ok) throw new Error('upstream_http_unavailable');
      const original = await raw.json(); forwardedRequests += calls.length;
      const delivered = structuredClone(original), replies = Array.isArray(delivered) ? delivered : [delivered];
      for (const call of calls) {
        if (mode === 'pass' || call.method !== 'eth_getTransactionReceipt' || !TX.test(call.params[0] ?? '')) continue;
        const target = await predicate({method:call.method,transactionHash:call.params[0].toLowerCase()});
        if (!target) continue;
        if (!UUID.test(target.runId ?? '') || !UUID.test(target.closureId ?? '') || target.taskId !== 'H1' ||
            !Number.isSafeInteger(target.taskIndex) || target.taskIndex < 0 || target.taskIndex > 11) {
          throw new Error('ber_receipt_fault_target_invalid');
        }
        const reply = replies.find(item => item?.id === call.id);
        if (!reply || reply.error || !reply.result || reply.result.transactionHash?.toLowerCase() !== call.params[0].toLowerCase() ||
            BigInt(reply.result.status ?? '-1') !== 1n) throw new Error('ber_receipt_fault_requires_actual_success');
        const originalReceipt = structuredClone(reply.result), selectedMode = mode;
        reply.result = selectedMode === 'missing' ? null : {...reply.result,status:'0x0'};
        const key = [target.runId,target.closureId,selectedMode,call.params[0].toLowerCase(),sha(originalReceipt)].join(':');
        const found = records.get(key), observedAt = new Date().toISOString();
        if (found) { found.count++; found.lastObservedAt = observedAt; }
        else {
          if (records.size >= 128) throw new Error('ber_receipt_fault_record_bound');
          records.set(key,{...target,mode:selectedMode,transactionHash:call.params[0].toLowerCase(),
            originalReceipt,originalReceiptSha256:sha(originalReceipt),deliveredReceipt:structuredClone(reply.result),
            deliveredReceiptSha256:sha(reply.result),count:1,firstObservedAt:observedAt,lastObservedAt:observedAt});
        }
      }
      response.writeHead(200,{'content-type':'application/json'}); response.end(JSON.stringify(delivered));
    } catch {
      rejectedRequests++; response.writeHead(503,{'content-type':'application/json'});
      response.end(JSON.stringify({error:'ber_observer_fault_proxy_unavailable'}));
    }
  });
  await new Promise((done,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',done);});
  return {
    origin:`http://127.0.0.1:${server.address().port}`,
    setTargetPredicate(value) { if(typeof value !== 'function')throw new Error('ber_receipt_target_predicate_invalid');predicate=value; },
    setMode(value) {
      if(!['pass','missing','conflicting'].includes(value))throw new Error('ber_receipt_fault_mode_invalid');
      if(value===mode)return;const now=new Date().toISOString();
      if(intervals.length)intervals.at(-1).endedAt=now;
      intervals.push({mode:value,startedAt:now,endedAt:null});mode=value;
    },
    snapshot() { return {schemaVersion:'ber-observer-receipt-fault/v1',
      boundary:'actual_local_chain_read_forwarding_with_explicit_target_closure_observer_response_fault',
      mode,forwardedRequests,rejectedRequests,intervals:structuredClone(intervals),interventions:structuredClone([...records.values()])}; },
    async close() { server.closeAllConnections();await new Promise((done,reject)=>server.close(error=>error?reject(error):done())); },
  };
}
