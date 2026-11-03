import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash,randomUUID} from 'node:crypto';
import {startMcdNativeFaultProxy} from './mcd-native-fault-proxy.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex');
async function upstream(t,handler){const s=http.createServer(handler);await new Promise(r=>s.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>s.close(r)));return 'http://127.0.0.1:'+s.address().port;}
async function proxy(t,origin,options={}){const p=await startMcdNativeFaultProxy({publicOrigin:'http://127.0.0.1:0',upstreamOrigin:origin,testOnlyEphemeralPorts:true,...options});t.after(()=>p.close());return p;}
function action(runId,operationId,kind='inspect_catalog'){return {jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'runs.task_action',arguments:{runId,taskIndex:0,operationId,command:{kind}}}};}

test('actual HTTP/SSE admission reply is dropped once only after complete verified upstream bytes; origin and credentials only transit RAM',async t=>{
  const runId=randomUUID(),actionId=randomUUID(),operationId='synthetic_operation_123',canary='CANARY-NEVER-PERSIST-AUTH',requests=[];let ended=false;
  const origin=await upstream(t,(req,res)=>{const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{
    requests.push({host:req.headers.host,authorization:req.headers.authorization,cookie:req.headers.cookie,body:Buffer.concat(chunks).toString('utf8')});
    res.writeHead(200,{'content-type':'text/event-stream'});res.write('event: message\ndata: '+JSON.stringify({jsonrpc:'2.0',id:1,result:{content:[{type:'text',text:JSON.stringify({admitted:true,runId,taskIndex:0,actionId,replayed:requests.length>1})}]}}));
    setTimeout(()=>{ended=true;res.end('\n\n');},20);
  });});
  const p=await proxy(t,origin,{onObservation:o=>{if(o.kind==='admission_response_dropped')assert(ended);}});p.arm({runId,operationIdHash:sha(operationId)});
  const options={method:'POST',headers:{host:'127.0.0.1:3000','content-type':'application/json',authorization:'Bearer '+canary,cookie:'session='+canary},body:JSON.stringify(action(runId,operationId))};
  await assert.rejects(fetch(p.origin+'/api/agent/mcp',options));
  const retry=await fetch(p.origin+'/api/agent/mcp',options);assert.equal(retry.status,200);await retry.text();
  assert.equal(requests.length,2);assert.equal(requests[0].host,new URL(p.origin).host);assert.equal(requests[0].authorization,'Bearer '+canary);assert.equal(requests[0].cookie,'session='+canary);
  assert.equal(p.observations.filter(o=>o.kind==='admission_response_dropped').length,1);const event=p.observations[0];assert.equal(event.actionId,actionId);assert.equal(event.runId,runId);assert.equal(event.operationIdHash,sha(operationId));assert.equal(event.wireFraming,'sse');assert(event.upstreamCompletedAt<=event.droppedAt);
  const replay=p.observations.find(o=>o.kind==='admission_retry_response');assert(replay);assert.equal(replay.replayed,true);assert.equal(replay.actionId,event.actionId);assert.equal(replay.operationIdHash,event.operationIdHash);assert.equal(replay.taskIndex,event.taskIndex);assert.equal(replay.wireFraming,'sse');assert(replay.enteredAt>=event.droppedAt);
  assert(!JSON.stringify(p.observations).includes(canary));assert(!JSON.stringify(p.observations).includes(operationId));assert(!JSON.stringify(p.observations).includes('authorization'));
});

test('wrong run, payment command, rejected or mismatched admission is forwarded rather than manufactured as response loss',async t=>{
  const runId=randomUUID(),operationId='synthetic_operation_456';let mode='wrong';
  const origin=await upstream(t,(req,res)=>{req.resume();req.on('end',()=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:1,result:{structuredContent:mode==='denied'?{admitted:false}:{admitted:true,runId:randomUUID(),taskIndex:0,actionId:randomUUID()}}}));});});
  const p=await proxy(t,origin);p.arm({runId,operationIdHash:sha(operationId)});
  for(const payload of [action(randomUUID(),operationId),action(runId,operationId,'pay'),action(runId,operationId)]){const r=await fetch(p.origin+'/api/agent/mcp',{method:'POST',body:JSON.stringify(payload)});assert.equal(r.status,200);await r.text();}
  mode='denied';const r=await fetch(p.origin+'/api/agent/mcp',{method:'POST',body:JSON.stringify(action(runId,operationId))});await r.text();assert.equal(p.dropped,false);assert(p.observations.every(o=>o.kind==='not_dropped_unverified_admission'));
});

test('real foreign-case rejection status is observed without copying body or cookies',async t=>{
  const foreignCaseId=randomUUID(),origin=await upstream(t,(req,res)=>{req.resume();req.on('end',()=>{res.writeHead(403);res.end('CANARY-PRIVATE-ERROR');});}),p=await proxy(t,origin,{foreignCaseId});
  const response=await fetch(p.origin+'/api/agent/mcp',{method:'POST',headers:{'x-w3bench-diagnostic-case':foreignCaseId,cookie:'CANARY-COOKIE'},body:'{"jsonrpc":"2.0","method":"initialize"}'});assert.equal(response.status,403);await response.text();
  assert.equal(p.observations[0].kind,'foreign_case_transport');assert.equal(p.observations[0].httpStatus,403);assert(!JSON.stringify(p.observations).includes('CANARY'));
});

test('proxy refuses remote origins, arbitrary production ports and replacement arming',async()=>{
  await assert.rejects(startMcdNativeFaultProxy({publicOrigin:'https://example.com',upstreamOrigin:'http://127.0.0.1:3001'}),/MCD_NATIVE_PROXY_ORIGIN_INVALID/);
  await assert.rejects(startMcdNativeFaultProxy({publicOrigin:'http://127.0.0.1:8784',upstreamOrigin:'http://127.0.0.1:3001'}),/MCD_NATIVE_PROXY_PORT_INVALID/);
});
test('observation details have a fixed bound and overflow remains explicit while actual responses still forward',async t=>{
  const foreignCaseId=randomUUID(),origin=await upstream(t,(req,res)=>{req.resume();req.on('end',()=>{res.writeHead(404);res.end('{}');});}),p=await proxy(t,origin,{foreignCaseId,observationLimit:1});
  for(let i=0;i<3;i++){const r=await fetch(p.origin+'/api/agent/mcp',{method:'POST',headers:{'x-w3bench-diagnostic-case':foreignCaseId},body:'{}'});assert.equal(r.status,404);await r.text();}
  assert.equal(p.observations.length,1);assert.equal(p.observationOverflowCount,2);assert.equal(p.captureOutcome,'partial_overflow');
});
test('aborted upstream response does not fabricate a complete admission or an intentional dropped receipt',async t=>{
  const runId=randomUUID(),operationId='synthetic_operation_aborted',origin=await upstream(t,(req,res)=>{req.resume();req.on('end',()=>{res.writeHead(200,{'content-type':'text/event-stream'});res.write('data: {"result":');setTimeout(()=>res.destroy(),5);});}),p=await proxy(t,origin);p.arm({runId,operationIdHash:sha(operationId)});
  await assert.rejects(async()=>{const r=await fetch(p.origin+'/api/agent/mcp',{method:'POST',body:JSON.stringify(action(runId,operationId))});await r.text();});assert.equal(p.dropped,false);assert.equal(p.observations.length,0);
});
