import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import {createRequire} from 'node:module';
import {createMcdCapacityHttp,deriveMcdEnvelopeMaximum} from './mcp-diagnostics-capacity-restore.mjs';
import {captureMcdColdRestore,observeMcdRestoreDiagnostics} from './mcp-diagnostics-cold-restore.mjs';

test('cold capture cannot be activated by serialized producer flags or read an original Google database',async()=>{
 const result=await captureMcdColdRestore({server:{status:'checkpoint_verified',writesMayBeEnabled:false,restoredAccessGrants:[]}});
 assert.equal(result.scenario006,undefined);assert.equal(result.blocked.reason,'actual_canonical_pending_outbox_or_operator_inputs_missing');
 await assert.rejects(observeMcdRestoreDiagnostics('postgres://oid_observer@postgres:5432/oid_google_local_11111111111111111111111111111111',['11111111-1111-4111-8111-111111111111']));
});

test('physical producer can export the actual Zod contract and construct its maximal finite accepted envelope',async t=>{
 const contract=await import('../../owner-identity/src/mcp-diagnostics-contract.ts');
 const {z}=createRequire(new URL('../../owner-identity/package.json',import.meta.url))('zod');
 const schema=z.toJSONSchema(contract.diagnosticEnvelopeSchema),maximum=deriveMcdEnvelopeMaximum(schema);maximum.source='client';
 assert.equal(contract.diagnosticEnvelopeSchema.safeParse(maximum).success,true);
 assert(Buffer.byteLength(contract.canonicalDiagnosticJson(maximum))<2048);
 assert.equal(Object.keys(maximum).length,Object.keys(schema.properties).length);
 t.diagnostic(JSON.stringify({maximalSafeEnvelopeBytes:Buffer.byteLength(contract.canonicalDiagnosticJson(maximum)),fields:Object.keys(maximum).length}));
});

test('capacity producer uses actual distinct source sockets and never forwarded IP headers or persisted bearer',async()=>{
 const observed=[];const server=http.createServer((request,response)=>{
  observed.push({source:request.socket.remoteAddress,forwarded:request.headers['x-forwarded-for']??null});
  request.resume();response.writeHead(429,{'content-type':'application/json'});response.end(JSON.stringify({error:{code:'DIAGNOSTICS_QUOTA_EXCEEDED',message:'synthetic unretained error text'}}));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const transport=createMcdCapacityHttp({origins:['http://127.0.0.1:'+server.address().port]});
  const first=await transport.request('/api/diagnostics/cases',{body:{diagnosticSessionId:'synthetic-fixture'},bearer:'synthetic-memory-only-bearer'});
  const second=await transport.request('/api/diagnostics/cases',{body:{diagnosticSessionId:'synthetic-fixture-2'}});
  assert.equal(first.transport.localAddress,'127.0.0.2');assert.equal(second.transport.localAddress,'127.0.0.3');
  assert.deepEqual(observed,[{source:'127.0.0.2',forwarded:null},{source:'127.0.0.3',forwarded:null}]);
  assert.equal(first.errorCode,'DIAGNOSTICS_QUOTA_EXCEEDED');assert.equal(first.httpStatus,429);
  const retained=JSON.stringify({first,second,sources:transport.sourceObservations});
  assert(!retained.includes('synthetic-memory-only-bearer'));assert(!retained.includes('synthetic unretained error text'));
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('capacity MCP requests cross the actual production remote profile with JSON and SSE plus its pinned protocol',async()=>{
 const {selectAgentMcpTransport}=await import('../../owner-identity/dist/agent-mcp-profile.js');
 const observed=[],config={publicOrigin:'http://127.0.0.1:3000',nodeEnv:'test',mcpTransportProfile:'remote-oauth-v1',mcpClientRegistry:[]};
 const server=http.createServer(async(request,response)=>{
  const chunks=[];for await(const chunk of request)chunks.push(chunk);
  try{const body=JSON.parse(Buffer.concat(chunks));const selected=selectAgentMcpTransport(config,false,body,request.headers);
   observed.push({selected,accept:request.headers.accept,protocol:request.headers['mcp-protocol-version']});const payload=JSON.stringify({jsonrpc:'2.0',id:body.id,result:{tools:[{name:'identity.preflight'}]}});if(observed.length===1){response.writeHead(200,{'content-type':'application/json'});response.end(payload);}else{response.writeHead(200,{'content-type':'text/event-stream'});response.end('event: message\ndata: '+payload+'\n\n');}
  }catch{response.writeHead(400,{'content-type':'application/json'});response.end(JSON.stringify({error:{code:'MCP_STREAMABLE_HTTP_REQUIRED'}}));}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const transport=createMcdCapacityHttp({origins:['http://127.0.0.1:'+server.address().port]});for(const framing of ['json','sse']){const result=await transport.request('/api/agent/mcp',{body:{jsonrpc:'2.0',id:'synthetic-protocol-regression-'+framing,method:'tools/list'}});assert.equal(result.httpStatus,200);assert.equal(result.resultKind,'tools');assert.equal(result.toolCount,1);assert.equal(result.wire.framing,framing);assert.equal(result.wire.hasMcpResponse,true);assert.equal(result.wire.rpcErrorCode,null);assert.equal(result.wire.resultIsError,false);}assert.deepEqual(observed,Array.from({length:2},()=>({selected:'remote-oauth',accept:'application/json, text/event-stream',protocol:'2025-06-18'})));}
 finally{await new Promise(resolve=>server.close(resolve));}
});
