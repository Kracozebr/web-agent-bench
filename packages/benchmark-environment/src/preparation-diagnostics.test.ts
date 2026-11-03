import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import test from 'node:test';
import {resetAnvilFork,AdminRpcFailure} from './chain.js';
import {GenerationFixtureFailure} from './fixtures.js';
import {createPreparationDiagnostics,PreparationHttpFailure,PREPARATION_PHASES} from './preparation-diagnostics.js';
import type {RuntimeManifest} from './manifest.js';

test('preparation failure records attempted versus confirmed stages without retaining source error/message/options',async()=>{
 for(const failed of PREPARATION_PHASES){
  const d=createPreparationDiagnostics();let captured:unknown;
  for(const phase of PREPARATION_PHASES){try{await d.at(phase,async()=>{if(phase===failed)throw Object.assign(new Error('RAW_SECRET_SENTINEL'),{url:'RAW_SECRET_SENTINEL'});return 1;});}catch(error){captured=error;break;}}
  const value=d.failure(captured);assert.equal(value.fixturePhase,failed);assert.equal(value.preparationProgress.attemptedPhase,failed);
  assert.deepEqual(value.preparationProgress.confirmedPhases,PREPARATION_PHASES.slice(0,PREPARATION_PHASES.indexOf(failed)));
  assert.equal(JSON.stringify(captured).includes('RAW_SECRET_SENTINEL'),false);assert.equal(JSON.stringify(value).includes('RAW_SECRET_SENTINEL'),false);
 }
});
test('actual finite RPC/HTTP/SQL metadata survives; arbitrary error code or message never becomes metadata',async()=>{
 const examples=[
  {source:new AdminRpcFailure({reason:'http_status',stage:'request',httpStatus:503}),expected:{fixtureAdminRpc:{reason:'http_status',stage:'request',httpStatus:503}}},
  {source:new PreparationHttpFailure(502),expected:{preparationHttpStatus:502}},
  {source:Object.assign(new Error('RAW_SECRET_SENTINEL'),{name:'DatabaseError',code:'57014'}),expected:{preparationSqlState:'57014'}},
 ];
 for(const{source,expected}of examples){const d=createPreparationDiagnostics();try{await d.at('persist_reset_proof',async()=>{throw source;});assert.fail();}catch(error){const value=d.failure(error);for(const[key,v]of Object.entries(expected))assert.deepEqual((value as Record<string,unknown>)[key],v);}}
 const d=createPreparationDiagnostics();try{await d.at('reserve_preparation',async()=>{throw{name:'RAW_SECRET_SENTINEL',code:'57014',message:'RAW_SECRET_SENTINEL'};});}catch(error){const v=d.failure(error);assert.equal(v.fixtureCauseClass,'OtherError');assert(!('preparationSqlState'in v));assert(!JSON.stringify(v).includes('RAW_SECRET_SENTINEL'));}
 assert.equal(d.failure(new GenerationFixtureFailure('send_transfer','AdminRpcFailure')).fixturePhase,'send_transfer');
});
test('real HTTP reset boundary distinguishes initial identity, reset response, and post-reset identity with unchanged call count',async()=>{
 // Synthetic HTTP codec fixture includes only fields read by assertAnvilIdentity; not a release manifest or live-chain proof.
 const manifest={local:{anvilVersion:'1.4.0',executionNetwork:'anvil',hardfork:'cancun',forkBlock:'0x10',chainId:31337},source:{blockNumber:'0x10',blockHash:'0x'+'a'.repeat(64)}} as unknown as RuntimeManifest;
 for(const failed of ['reset_identity_before','reset_rpc','reset_identity_after',null] as const){
  const methods:string[]=[];let resetSeen=false;
  const server=createServer(async(req,res)=>{let bytes='';for await(const chunk of req)bytes+=chunk;const{method}=JSON.parse(bytes)as{method:string};methods.push(method);
   if((failed==='reset_identity_before'&&!resetSeen&&method==='web3_clientVersion')||(failed==='reset_rpc'&&method==='anvil_reset')||(failed==='reset_identity_after'&&resetSeen&&method==='web3_clientVersion')){res.statusCode=503;res.end('RAW_SECRET_SENTINEL');return;}
   const result=method==='web3_clientVersion'?'anvil/v1.4.0':method==='anvil_nodeInfo'?{network:'anvil',hardFork:'cancun',forkConfig:{forkBlockNumber:'0x10'}}:method==='eth_chainId'?'0x7a69':method==='eth_getBlockByNumber'?{hash:manifest.source.blockHash,number:'0x10'}:null;
   if(method==='anvil_reset')resetSeen=true;res.setHeader('content-type','application/json');res.end(JSON.stringify({id:1,result}));});
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const address=server.address();assert(address&&typeof address!=='string');const d=createPreparationDiagnostics();
  try{if(failed){await assert.rejects(resetAnvilFork(`http://127.0.0.1:${address.port}`,'http://unused.test',manifest,d.at),error=>{const v=d.failure(error);assert.equal(v.fixturePhase,failed);assert.equal(JSON.stringify(v).includes('RAW_SECRET_SENTINEL'),false);assert.equal(v.preparationProgress.confirmedPhases.includes('reset_rpc'),failed==='reset_identity_after');return true;});}
   else{await resetAnvilFork(`http://127.0.0.1:${address.port}`,'http://unused.test',manifest,d.at);assert.deepEqual(d.failure(null).preparationProgress.confirmedPhases,['reset_identity_before','reset_rpc','reset_identity_after']);}
   assert.equal(methods.length,failed==='reset_identity_before'?1:failed==='reset_rpc'?5:failed==='reset_identity_after'?6:9);
  }finally{await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
 }
});
