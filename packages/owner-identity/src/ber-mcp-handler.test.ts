import assert from 'node:assert/strict';
import test from 'node:test';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { registerRunIntentMcpTools } from './run-routes.js';
import { AGENT_MCP_INPUT_ELEMENTS } from './mcp-input-bounds.js';
import Fastify from 'fastify';
import { registerAgentRoutes, type AgentRouteDependencies } from './agents.js';
import { HttpError } from './http-error.js';

test('authenticated malformed inputs consume credential rate budget before bounded rejection', async () => {
  const origin = 'http://127.0.0.1:8784';
  const resource = origin + '/api/agent';
  const row = { credentialId:'fixture-credential',grantId:'g',ownerId:'o',agentId:'a',resource,role:'agent',
    grantGeneration:1,accessGeneration:1,grantExpiresAt:new Date(Date.now()+60_000),grantRevokedAt:null,
    accessRevokedAt:null,admissionStatus:'admitted',training:true,ranked:true,policyRevision:1,accessRevision:1 };
  // Only the database credential lookup is stubbed; the production HTTP ingress,
  // principal checks, transport selection, limiter ordering and bounds run unchanged.
  const query = { from(){return this;},innerJoin(){return this;},where(){return this;},async limit(){return [row];} };
  let credentialCalls=0, ipCalls=0, toolRegistrations=0;
  const deps = { db:{select:()=>query}, config:{publicOrigin:origin,apiHost:'127.0.0.1',apiPort:8784,
    mcpTransportProfile:'strict-2026-07-28',nodeEnv:'test'}, agentResource:resource, preflightRateLimitMax:6,
    rateLimit:async (_request:unknown,group:string,limit:number)=>{
      if(group==='agent-mcp-ip'){ipCalls++;assert.equal(limit,300);}
      if(group==='agent-preflight-fixture-credential'){
        credentialCalls++;assert.equal(limit,6);
        if(credentialCalls>limit)throw new HttpError(429,'RATE_LIMITED','Request budget exhausted');
      }
    }, registerMcpTools:()=>{toolRegistrations++;},
  } as unknown as AgentRouteDependencies;
  const app=Fastify({logger:false});
  app.setErrorHandler((error,_request,reply)=>reply.code(error instanceof HttpError?error.status:500).send({error:'request_rejected'}));
  registerAgentRoutes(app,deps);
  let deep:unknown={};for(let i=0;i<12;i++)deep={child:deep};
  const request=(args:unknown,id:unknown=1)=>app.inject({method:'POST',url:'/api/agent/mcp',headers:{host:'127.0.0.1:8784',origin,
    authorization:'Bearer aap1_'+'a'.repeat(43),'content-type':'application/json','mcp-method':'tools/call',
    'mcp-protocol-version':'2026-07-28'},payload:{jsonrpc:'2.0',id,method:'tools/call',params:{name:'runs.finish_task',arguments:args}}});
  try {
    assert.equal((await request(deep)).statusCode,400);
    assert.equal((await request(Array(513).fill(1))).statusCode,400);
    for(const id of [{ privateNestedField:'caller_data' }, ['caller_data']]) {
      const response=await request(deep,id);
      assert.equal(response.statusCode,400);assert.equal(response.json().id,null);
      assert.doesNotMatch(response.body,/caller_data|privateNestedField/);
    }
    for(const id of ['valid-correlation',42]) {
      const response=await request(deep,id);
      assert.equal(response.statusCode,400);assert.equal(response.json().id,id);
    }
    assert.equal((await request(deep)).statusCode,429);
    assert.equal(credentialCalls,7);assert.equal(ipCalls,7);
    assert.equal(toolRegistrations,0,'denied requests must not construct tools or reach mutation handlers');
  } finally {await app.close();}
});

// Real SDK + production tool registration, isolated DB sentinel. This tests
// protocol/schema reachability only, not admission, PostgreSQL or native-agent E2E.
test('actual MCP handler admits representable swap and full S2 input to production tool callbacks', async () => {
  let reachedDatabase = 0;
  const deps = { db: { transaction: async () => { reachedDatabase++; throw Error('isolated_database_boundary'); } } };
  const principal = {ownerId:'11111111-1111-4111-8111-111111111111',agentId:'22222222-2222-4222-8222-222222222222',accessGeneration:1,grantId:'33333333-3333-4333-8333-333333333333'};
  const handler = createMcpHandler(()=>{
    const server = new McpServer({name:'test',version:'1'}, {supportedProtocolVersions:['2025-06-18'],maxToolInputElements:AGENT_MCP_INPUT_ELEMENTS});
    registerRunIntentMcpTools(server,principal as never,deps as never);return server;
  });
  const target = {runId:'44444444-4444-4444-8444-444444444444',taskIndex:1,operationId:'ber_test_operation_001'};
  async function call(name:string,args:unknown, invalid=false){
    const body={jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}};
    const response=await handler.fetch(new Request('http://127.0.0.1/api/agent/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify(body)}),{parsedBody:body});
    const text=await response.text();
    if(invalid) assert.match(text,/Invalid arguments for tool/);
    else assert.doesNotMatch(text,/maximum of|Invalid arguments for tool/);
    return text;
  }
  try {
    await call('runs.task_action',{...target,command:{kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',amountInUnits:'1',amountOutMinimumUnits:'1',recipient:'0x'+'1'.repeat(40),gasLimit:'1',feeTier:3000}});
    assert.equal(reachedDatabase,1);
    await call('runs.finish_task',{...target,answer:{amountUnits:'1',network:'net',assetId:'USDC',recipient:'recipient',scheme:'exact',resourceId:'r',offerId:'o',version:'v',authFields:Array.from({length:128},()=>({name:'a',value:'b'}))}});
    assert.equal(reachedDatabase,2);
    await call('runs.task_action',{...target,command:{kind:'swap',arbitraryRpc:'forbidden'}},true);
    assert.equal(reachedDatabase,2,'malformed commands must not reach admission/database');
  } finally { await handler.close(); }
});
