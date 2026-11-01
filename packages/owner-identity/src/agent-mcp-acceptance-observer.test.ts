import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {projectAgentMcpAcceptance,createAgentMcpAcceptanceObserver} from './agent-mcp-acceptance-observer.js';
const ownerId='10000000-0000-4000-8000-000000000001',agentId='10000000-0000-4000-8000-000000000002',grantId='10000000-0000-4000-8000-000000000003';
test('ACI observer retains only scoped protocol identifiers, never arbitrary tool/OAuth/model text',()=>{
  const secret='CANARY_OAUTH_PROVIDER_TOKEN_DO_NOT_CAPTURE';
  const request=projectAgentMcpAcceptance({requestId:ownerId,phase:'request',body:{id:secret,method:'tools/call',params:{name:'identity.preflight',arguments:{agentId,access_token:secret,title:secret}}},principal:{ownerId,agentId,grantId,...{secret}}});
  const response=projectAgentMcpAcceptance({requestId:ownerId,phase:'response',body:{id:secret,result:{content:[{type:'text',text:JSON.stringify({status:'allowed',identity:{ownerId,agentId,grantId,email:secret},access_token:secret,run:{terminalReason:'coordinator_'+secret}})}],rawPayload:secret}}});
  assert.equal(request.projection.toolName,'identity.preflight');assert.deepEqual(request.projection.arguments,{agentId});
  assert.equal(JSON.stringify([request,response]).includes(secret),false);
  assert.deepEqual(request.principal,{ownerId,agentId,grantId});
  assert.deepEqual(response.projection.content,[{status:'allowed',identity:{ownerId,agentId,grantId},run:{}}]);
  assert.deepEqual(request.projection.rpcId,response.projection.rpcId);
});
test('ACI observer accepts new version metadata but never unknown tool bodies or unbounded recursion',()=>{
  const init=projectAgentMcpAcceptance({requestId:ownerId,phase:'request',body:{id:1,method:'initialize',params:{protocolVersion:'2026-07-28',clientInfo:{name:'unknown-capable-client',version:'997.123.42'}}}});
  assert.equal(init.projection.clientVersion,'997.123.42');assert.equal(init.projection.protocolVersion,'2026-07-28');
  const nested:{run?:unknown}={};nested.run=nested;
  assert.throws(()=>projectAgentMcpAcceptance({requestId:ownerId,phase:'response',body:{result:nested}}));
  const unknown=projectAgentMcpAcceptance({requestId:ownerId,phase:'request',body:{id:1,method:'tools/call',params:{name:'secret-tool',arguments:{secret:'canary'}}}});
  assert.equal(unknown.projection.toolName,undefined);assert.equal(unknown.projection.arguments,undefined);
});
test('ACI observer refuses production and non-disposable databases before creating files',async()=>{
  const options={enabled:true,nodeEnv:'development',databaseName:'oid_acceptance_'+'a'.repeat(32),repoRoot:process.cwd(),captureId:ownerId,publicOrigin:'http://127.0.0.1:3000'};
  for(const changes of [{nodeEnv:'production'},{enabled:false},{databaseName:'web_agent_bench'},{publicOrigin:'https://example.com'},{captureId:'../secret'}])await assert.rejects(createAgentMcpAcceptanceObserver({...options,...changes}),/aci_observer_not_disposable/);
});
test('ACI observer writes independent process epochs and persists bounded recording failures without throwing to MCP',async()=>{
  const base=await mkdtemp(resolve(tmpdir(),'aci-observer-unit-'));
  const options={enabled:true,nodeEnv:'development',databaseName:'oid_acceptance_'+'a'.repeat(32),repoRoot:base,captureId:ownerId,publicOrigin:'http://127.0.0.1:3000'};
  try{
    const first=await createAgentMcpAcceptanceObserver(options);
    first.observe({requestId:ownerId,phase:'response',httpStatus:401,authenticateScheme:'Bearer',body:{error:{code:-32001,message:'CANARY_ACCESS_TOKEN'}}});
    const one=await first.close();assert.equal(one.records,1);assert.deepEqual(one.errors,[]);
    const second=await createAgentMcpAcceptanceObserver(options);
    second.observe({requestId:ownerId,phase:'request',body:{id:1,method:'tools/list'}});
    second.observe({requestId:ownerId,phase:'request',body:{large:'x'.repeat(70000)}});
    const two=await second.close();assert.notEqual(one.epoch,two.epoch);assert.deepEqual(two.errors,['projection_failed']);
    const text=await readFile(one.path,'utf8');assert.equal(text.includes('CANARY_ACCESS_TOKEN'),false);
    const packets=text.trim().split('\n').map(x=>JSON.parse(x));assert.deepEqual(packets.map(x=>x.sequence),[1,1]);assert.equal(packets[0].authenticateScheme,'Bearer');
    const names=await readdir(resolve(base,'artifacts/runs/agent-client-connection',ownerId));assert.equal(names.filter(x=>x.endsWith('-status.json')).length,2);
  }finally{
    const expected=resolve(tmpdir())+sep;if(!resolve(base).startsWith(expected)||!base.split(sep).at(-1)?.startsWith('aci-observer-unit-'))throw new Error('unsafe_test_cleanup');
    await rm(base,{recursive:true,force:false});
  }
});
