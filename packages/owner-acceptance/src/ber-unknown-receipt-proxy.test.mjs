import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import test from 'node:test';
import {startBerUnknownReceiptProxy} from './ber-unknown-receipt-proxy.mjs';

test('H1 observer fault preserves upstream receipt and only changes receipt reads for the exact closed target',async()=>{
  const tx='0x'+'1'.repeat(64), receipt={transactionHash:tx,status:'0x1',logs:[]};let upstreamCalls=0;
  const upstream=createServer(async(request,response)=>{let data='';for await(const bytes of request)data+=bytes;
    const call=JSON.parse(data);upstreamCalls++;response.setHeader('content-type','application/json');
    response.end(JSON.stringify({jsonrpc:'2.0',id:call.id,result:call.method==='eth_getTransactionReceipt'?receipt:'0x2105'}));});
  await new Promise(done=>upstream.listen(0,'127.0.0.1',done));
  const proxy=await startBerUnknownReceiptProxy({upstreamOrigin:`http://127.0.0.1:${upstream.address().port}`});
  const call=async(method='eth_getTransactionReceipt')=>(await fetch(proxy.origin,{method:'POST',body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:method==='eth_getTransactionReceipt'?[tx]:[]})})).json();
  try{
    proxy.setMode('missing');assert.deepEqual((await call()).result,receipt);
    proxy.setTargetPredicate(async()=>({runId:'10000000-0000-4000-8000-000000000001',taskIndex:8,
      closureId:'20000000-0000-4000-8000-000000000002',taskId:'H1'}));
    assert.equal((await call()).result,null);assert.equal((await call('eth_chainId')).result,'0x2105');
    proxy.setMode('conflicting');assert.equal((await call()).result.status,'0x0');assert.equal(receipt.status,'0x1');
    proxy.setMode('pass');assert.deepEqual((await call()).result,receipt);
    const proof=proxy.snapshot();assert.equal(proof.interventions.length,2);
    assert.ok(proof.interventions.every(i=>i.originalReceipt.status==='0x1'&&i.originalReceipt.transactionHash===tx));
    const before=upstreamCalls;const denial=await call('eth_sendRawTransaction');assert.equal(denial.error,'ber_observer_fault_proxy_unavailable');
    assert.equal(upstreamCalls,before,'economic RPC never forwarded');
  }finally{await proxy.close();upstream.closeAllConnections();await new Promise(done=>upstream.close(done));}
});
