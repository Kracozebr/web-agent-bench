import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdtemp,mkdir,writeFile,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {startNativeProxy,projectNativeRequest,projectNativeResponse,projectNativeResponseBytes,createArcNativeIntentRunner,privateCaptureDirectory,sha256} from './arc-native-bridge.mjs';
import {transformNativeHelper} from './run_arc_native.mjs';

test('native trace projections omit arbitrary bodies, headers, signatures and answer bytes',()=>{
 const secret='SECRET_NEVER_PERSISTED';
 const request=projectNativeRequest({id:1,method:'tools/call',params:{name:'runs.task_action',arguments:{runId:'abcd-1234',taskIndex:1,operationId:'op-1',command:{kind:'pay',signature:secret,body:secret},answer:secret,authorization:secret}}});
 assert.deepEqual(request,{id:1,method:'tools/call',toolName:'runs.task_action',arguments:{runId:'abcd-1234',taskIndex:1,operationId:'op-1'},command:{kind:'pay'}});
 const response=projectNativeResponse({id:1,result:{content:[{type:'text',text:JSON.stringify({state:'task_ready',run:{runId:'abcd-1234',status:'running',terminal:false},task:{runId:'abcd-1234',taskIndex:1,taskId:'M1',participantToolProtocol:'separate_payment_retrieval_v1',conditions:secret},resource:secret,signature:secret})}]}});
 assert.equal(response.content[0].task.participantToolProtocol,'separate_payment_retrieval_v1');assert.ok(!JSON.stringify(response).includes(secret));
 assert.deepEqual(projectNativeRequest({method:'initialize',params:{protocolVersion:'2025-06-18',clientInfo:{name:'codex',version:'0.165.0',arbitrary:secret}}}).initialize,{protocolVersion:'2025-06-18',clientInfo:{name:'codex',version:'0.165.0'}});
});

test('finite native SSE projects exactly one JSON-RPC response including CRLF and multiline data',()=>{
 const json={jsonrpc:'2.0',id:12,result:{structuredContent:{state:'terminal',run:{runId:'run-1',status:'completed',terminal:true},task:null},content:[]}};
 const expected=projectNativeResponse(json);
 assert.deepEqual(projectNativeResponseBytes(Buffer.from('event: message\ndata: '+JSON.stringify(json)+'\n\n'),'text/event-stream'),expected);
 const text=JSON.stringify(json);const comma=text.indexOf(',');
 const multiline=': keepalive\r\n\r\nevent: message\r\nid: NONSENSITIVE_IGNORED\r\ndata: '+text.slice(0,comma+1)+'\r\ndata: '+text.slice(comma+1)+'\r\n\r\n';
 assert.deepEqual(projectNativeResponseBytes(Buffer.from(multiline),'text/event-stream; charset=utf-8'),expected);
});

test('SSE multiple, malformed, incomplete and excessive frames never collapse into a terminal proof or leak raw text',()=>{
 const secret='SECRET_NEVER_PERSISTED';
 const message=id=>({jsonrpc:'2.0',id,result:{structuredContent:{state:'terminal',run:{runId:'run-1',status:'completed',terminal:true},secret}}});
 const frame=id=>'data: '+JSON.stringify(message(id))+'\n\n';
 const multiple=projectNativeResponseBytes(Buffer.from(frame(1)+frame(2)),'text/event-stream');
 assert.equal(multiple.sseFrames.length,2);assert.deepEqual(multiple.sseFrames.map(x=>[x.frameIndex,x.projection.id]),[[0,1],[1,2]]);assert.equal(multiple.result,undefined);assert.ok(!JSON.stringify(multiple).includes(secret));
 const malformed=projectNativeResponseBytes(Buffer.from('data: '+secret+'\n\n'+frame(2)),'text/event-stream');assert.equal(malformed.malformedFrameCount,1);assert.equal(malformed.result,undefined);assert.ok(!JSON.stringify(malformed).includes(secret));
 const incomplete=projectNativeResponseBytes(Buffer.from(frame(1)+'data: '+JSON.stringify(message(2))),'text/event-stream');assert.equal(incomplete.incompleteDataFrame,true);assert.equal(incomplete.result,undefined);
 const excessive=projectNativeResponseBytes(Buffer.from(Array.from({length:129},(_,i)=>frame(i)).join('')),'text/event-stream');assert.deepEqual(excessive,{nonJson:true,sseFrameLimitExceeded:true});
 assert.deepEqual(projectNativeResponseBytes(Buffer.from(secret),'application/json'),{nonJson:true});
});

test('proxy forwards finite native SSE bytes unchanged while preserving native terminal projection and raw SHA',async()=>{
 const bearer='test-only-native-sse-bearer-123';
 const raw='event: message\r\ndata: '+JSON.stringify({jsonrpc:'2.0',id:5,result:{structuredContent:{state:'terminal',run:{runId:'run-1',status:'completed',terminal:true},task:null},content:[]}})+'\r\n\r\n';
 const target=createServer((req,res)=>{req.resume();res.setHeader('content-type','text/event-stream');res.end(raw);});
 await new Promise(done=>target.listen(0,'127.0.0.1',done));
 const proxy=await startNativeProxy({publicOrigin:`http://127.0.0.1:${target.address().port}`,agentBearer:bearer,port:0});
 try{
  const response=await fetch(`http://127.0.0.1:${proxy.port}/api/agent/mcp`,{method:'POST',headers:{authorization:`Bearer ${bearer}`},body:JSON.stringify({jsonrpc:'2.0',id:5,method:'tools/call',params:{name:'runs.current_task',arguments:{runId:'run-1'}}})});
  assert.equal(await response.text(),raw);assert.equal(response.headers.get('content-type'),'text/event-stream');
  const packet=proxy.trace[1];assert.equal(packet.rawSha256,sha256(Buffer.from(raw)));assert.equal(packet.rawPersisted,false);assert.equal(packet.projection.id,5);assert.equal(packet.projection.result.run.terminal,true);assert.equal(packet.projection.result.run.status,'completed');
 }finally{await proxy.close();await new Promise(done=>target.close(done));}
});

test('proxy accepts exact MCP POST with correct credential and overwrites upstream host; wire proof bounded and secret free',async()=>{
 const bearer='test-only-private-bearer-123456';let count=0;
 const target=createServer(async(req,res)=>{count++;assert.equal(req.url,'/api/agent/mcp');assert.equal(req.headers.host,`127.0.0.1:${target.address().port}`);assert.equal(req.headers.authorization,`Bearer ${bearer}`);let body='';for await(const chunk of req)body+=chunk;assert.equal(JSON.parse(body).method,'tools/call');res.setHeader('content-type','application/json');res.end(JSON.stringify({jsonrpc:'2.0',id:4,result:{content:[{type:'text',text:JSON.stringify({state:'terminal',run:{runId:'run-1',status:'completed',terminal:true},hidden:bearer})}]}}));});
 await new Promise(done=>target.listen(0,'127.0.0.1',done));
 const proxy=await startNativeProxy({publicOrigin:`http://127.0.0.1:${target.address().port}`,agentBearer:bearer,port:0,maxBytes:2048});
 try{
  const base=`http://127.0.0.1:${proxy.port}`;
  assert.equal((await fetch(base+'/wrong',{method:'POST'})).status,404);
  assert.equal((await fetch(base+'/api/agent/mcp')).status,404);
  assert.equal((await fetch(base+'/api/agent/mcp',{method:'POST',headers:{authorization:'Bearer wrong'}})).status,401);
  const response=await fetch(base+'/api/agent/mcp',{method:'POST',headers:{authorization:`Bearer ${bearer}`},body:JSON.stringify({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'runs.current_task',arguments:{runId:'run-1'}}})});
  assert.equal(response.status,200);assert.equal(count,1);assert.equal(proxy.trace.length,2);assert.equal(proxy.trace[1].projection.content[0].run.terminal,true);assert.ok(!JSON.stringify(proxy.trace).includes(bearer));assert.match(proxy.trace[0].rawSha256,/^[a-f0-9]{64}$/);
  assert.equal((await fetch(base+'/api/agent/mcp',{method:'POST',headers:{authorization:`Bearer ${bearer}`},body:'x'.repeat(2049)})).status,413);assert.equal(count,1);
 }finally{await proxy.close();await new Promise(done=>target.close(done));}
});

test('private helper derives only alias, endpoint and explicit no-daemon changes',async()=>{
 const source=await readFile(new URL('../infrastructure/owner-identity/run-codex-google-local.mjs',import.meta.url),'utf8');
 const derived=transformNativeHelper(source);
 assert.ok(derived.includes("'--no-daemon', 'exec'"));assert.ok(derived.includes('http://127.0.0.1:39001/api/agent/mcp'));assert.ok(!derived.includes('owner_identity'));
 assert.equal(derived.replaceAll('w3bench_user','owner_identity').replace('http://127.0.0.1:39001/api/agent/mcp','http://127.0.0.1:3000/api/agent/mcp').replace("'--no-daemon', 'exec'","'exec'"),source);
 assert.throws(()=>transformNativeHelper(source.replace("'exec', '--ephemeral'","'other', '--ephemeral'")),/source_drift/);
});

test('callback binds exact UI prompt to job and completion then removes only its credential',async()=>{
 const repoRoot=await mkdtemp(resolve(tmpdir(),'arc-native-unit-'));const captureId='unit-test';const directory=privateCaptureDirectory(repoRoot,captureId);
 const bearer='test-only-private-bearer-abcdef';const prompt='Exact UI handoff\nwith trailing newline\n';
 const runner=createArcNativeIntentRunner({repoRoot,captureId,port:0,timeoutMs:5000});
 try{
  const pending=runner({agentBearer:bearer,agentId:'agent-1',intentId:'intent-1',handoffPrompt:prompt,publicOrigin:'http://127.0.0.1:3000'});
  let job;for(let i=0;i<100;i++){job=await readFile(resolve(directory,'job.json'),'utf8').then(JSON.parse).catch(()=>null);if(job)break;await new Promise(done=>setTimeout(done,10));}
  assert.ok(job);assert.equal(job.promptSha256,sha256(Buffer.from(prompt)));assert.equal(await readFile(resolve(directory,'handoff.txt'),'utf8'),prompt);assert.ok(!JSON.stringify(job).includes(bearer));
  await writeFile(resolve(directory,'other.txt'),'keep');
  await writeFile(resolve(directory,'completed.json'),JSON.stringify({jobId:job.jobId,promptSha256:job.promptSha256,native:{implementation:'fake_unit_only',promptSha256:job.promptSha256},sourcePins:{},helperSummary:{}}));
  const result=await pending;assert.equal(result.implementation,'fake_unit_only');assert.equal(result.wireTrace.packets.length,0);await assert.rejects(access(resolve(directory,'credential.txt')));assert.equal(await readFile(resolve(directory,'other.txt'),'utf8'),'keep');
 }finally{
  // Only this generated unit fixture directory is removed; never a configured capture directory.
  assert.ok(repoRoot.startsWith(resolve(tmpdir())+String.fromCharCode(92))||repoRoot.startsWith(resolve(tmpdir())+'/'));assert.match(repoRoot.split(/[\\/]/).at(-1),/^arc-native-unit-/);await rm(repoRoot,{recursive:true,force:true});
 }
});
