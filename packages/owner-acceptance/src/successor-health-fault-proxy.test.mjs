import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {startSuccessorHealthFaultProxy} from './successor-health-fault-proxy.mjs';

test('only exact health reads after a confirmed predecessor are denied; mutations and reset pass through',async()=>{
  const requests=[];const upstream=createServer((req,res)=>{requests.push({method:req.method,path:req.url});res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({status:'ready'}));});
  await new Promise(r=>upstream.listen(0,'127.0.0.1',r));
  const proxy=await startSuccessorHealthFaultProxy({upstreamOrigin:`http://127.0.0.1:${upstream.address().port}`});
  try{
    let terminal=false;
    proxy.arm(async()=>terminal?{runId:'8f3a8888-1111-4111-8111-111111111111',taskIndex:0,predecessorFinishedAt:'2026-11-01T00:00:00.000Z'}:null);
    assert.equal((await fetch(proxy.origin+'/healthz')).status,200);assert.equal(proxy.snapshot().interventions.length,0);
    terminal=true;
    assert.equal((await fetch(proxy.origin+'/healthz')).status,503);assert.equal(proxy.snapshot().interventions.length,1);
    assert.equal((await fetch(proxy.origin+'/internal/action',{method:'POST',headers:{authorization:'Bearer synthetic-canary'},body:'synthetic-body'})).status,200);
    assert.equal((await fetch(proxy.origin+'/healthz',{method:'POST'})).status,200);
    assert.equal(requests.filter(x=>x.method==='GET'&&x.path==='/healthz').length,1);
    assert(!JSON.stringify(proxy.snapshot()).includes('synthetic-canary'));assert(!JSON.stringify(proxy.snapshot()).includes('synthetic-body'));
    terminal=false;assert.equal((await fetch(proxy.origin+'/healthz')).status,200);assert.equal(proxy.snapshot().interventions.length,1);
    proxy.reset();assert.equal((await fetch(proxy.origin+'/healthz')).status,200);
  }finally{await proxy.close();await new Promise(r=>upstream.close(r));}
});

test('unconfirmed predicate failure cannot claim an intervention',async()=>{
  const upstream=createServer((_req,res)=>res.writeHead(200).end());await new Promise(r=>upstream.listen(0,'127.0.0.1',r));
  const proxy=await startSuccessorHealthFaultProxy({upstreamOrigin:`http://127.0.0.1:${upstream.address().port}`});
  try{proxy.arm(async()=>{throw new Error('synthetic_read_failure')});assert.equal((await fetch(proxy.origin+'/healthz')).status,200);assert.equal(proxy.snapshot().interventions.length,0);assert.equal(proxy.snapshot().predicateErrors,1);}finally{await proxy.close();await new Promise(r=>upstream.close(r));}
});
