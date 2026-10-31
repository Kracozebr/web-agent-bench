import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import test from 'node:test';
import {AdminRpcFailure, setAnvilBalance} from './chain.js';

// Real HTTP exchanges protect classification at the private RPC boundary without a live fork.
test('balance fixture diagnoses HTTP/RPC/set/readback failures without leaking response data or resending', async () => {
  const sentinel = 'RAW_SECRET_SENTINEL';
  const address = `0x${'1'.repeat(40)}` as const;
  const cases = [
    {kind:'http', expected:{reason:'http_status', stage:'set', httpStatus:503}, requests:1},
    {kind:'rpc', expected:{reason:'rpc_error', stage:'set', rpcCode:-32000}, requests:1},
    {kind:'ack', expected:{reason:'unexpected_set_balance_ack', stage:'set'}, requests:1},
    {kind:'mismatch', expected:{reason:'balance_mismatch', stage:'readback'}, requests:2},
    {kind:'invalid_read', expected:{reason:'invalid_balance_readback', stage:'readback'}, requests:2},
    {kind:'read_rpc', expected:{reason:'rpc_error', stage:'readback', rpcCode:-32603}, requests:2},
    {kind:'json', expected:{reason:'invalid_json', stage:'set'}, requests:1},
    {kind:'envelope', expected:{reason:'invalid_rpc_envelope', stage:'set'}, requests:1},
    {kind:'success', expected:null, requests:2},
  ];
  for (const variant of cases) {
    let count = 0;
    const server = createServer(async (request,response) => {
      let input = '';for await(const chunk of request) input += chunk;
      const {method} = JSON.parse(input) as {method:string}; count++;
      response.setHeader('content-type','application/json');
      if(variant.kind === 'http') {response.statusCode=503;response.end(sentinel);return;}
      if(variant.kind === 'json') {response.end(sentinel);return;}
      const body = variant.kind === 'envelope' ? {id:2,result:sentinel} :
        variant.kind === 'rpc' || (variant.kind === 'read_rpc' && method==='eth_getBalance') ?
          {id:1,error:{code:variant.kind === 'rpc' ? -32000 : -32603,message:sentinel,data:{privateKey:sentinel}}} :
          {id:1,result:method==='anvil_setBalance' ? variant.kind==='ack' ? sentinel : null :
            variant.kind==='mismatch' ? '0x2' : variant.kind==='invalid_read' ? sentinel : '0x1'};
      response.end(JSON.stringify(body));
    });
    await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
    const listening=server.address();assert.ok(listening&&typeof listening!=='string');
    try {
      if(variant.expected === null) await setAnvilBalance(`http://127.0.0.1:${listening.port}`,address,'0x1');
      else await assert.rejects(setAnvilBalance(`http://127.0.0.1:${listening.port}`,address,'0x1'), error=>{
        assert.ok(error instanceof AdminRpcFailure);
        assert.deepEqual(error.diagnostic,variant.expected);
        assert.equal(JSON.stringify(error).includes(sentinel),false);
        assert.equal(error.message.includes(address),false);
        return true;
      });
      assert.equal(count,variant.requests,variant.kind);
    } finally {await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
  }
});
