import assert from 'node:assert/strict';import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';import test from 'node:test';
import {createRpcProxy} from './proxy.js';import {loadManifest} from './manifest.js';

const key='source-proxy-recovery-test-key-not-a-secret';
async function fixture(work:(request:IncomingMessage,response:ServerResponse,body:string,count:number)=>void|Promise<void>,run:(proxy:Awaited<ReturnType<typeof createRpcProxy>>,bodies:string[])=>Promise<void>,local=false){
 const bodies:string[]=[];const server=createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;bodies.push(body);await work(req,res,body,bodies.length);});
 await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));const address=server.address();assert.ok(address&&typeof address!=='string');
 const names=['BEF_PROXY_MODE','BEF_SOURCE_RPC_URL','BEF_SOURCE_RPC_URL_FILE','BEF_PROXY_PORT','BEF_SERVICE_KEY','BEF_SERVICE_KEY_FILE','BEF_ENV_ID','BEF_RPC_TARGET_URL'];
 const previous=new Map(names.map(n=>[n,process.env[n]]));const originalFetch=globalThis.fetch;
 process.env.BEF_PROXY_MODE=local?'local':'source';process.env.BEF_SOURCE_RPC_URL=`http://127.0.0.1:${address.port}`;delete process.env.BEF_SOURCE_RPC_URL_FILE;
 process.env.BEF_PROXY_PORT='8545';process.env.BEF_SERVICE_KEY=key;delete process.env.BEF_SERVICE_KEY_FILE;
 if(local){process.env.BEF_ENV_ID='bef-env-a';process.env.BEF_RPC_TARGET_URL='http://anvil-a:8545';globalThis.fetch=(input,init)=>originalFetch(String(input).startsWith('http://anvil-a:8545')?`http://127.0.0.1:${address.port}`:input,init);}
 const proxy=await createRpcProxy();
 try{await run(proxy,bodies);}finally{await proxy.close();globalThis.fetch=originalFetch;for(const [name,value]of previous)value===undefined?delete process.env[name]:process.env[name]=value;await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));}
}
const request=(id=1)=>({jsonrpc:'2.0',id,method:'eth_chainId',params:[]});
async function metrics(proxy:Awaited<ReturnType<typeof createRpcProxy>>){return (await proxy.inject({method:'GET',url:'/internal/admin/metrics',headers:{'x-bef-service-key':key}})).json();}

test('production Fastify source proxy retries disconnected validated batch exactlyonce with identical bytes and budget',async()=>{
 await fixture((req,res,body,count)=>{if(count===1){req.socket.destroy();return;}res.setHeader('content-type','application/json');res.end(JSON.stringify(JSON.parse(body).map((r:{id:number})=>({jsonrpc:'2.0',id:r.id,result:'0x2105'}))));},async(proxy,bodies)=>{
  const response=await proxy.inject({method:'POST',url:'/',payload:[request(1),request(2)]});assert.equal(response.statusCode,200);assert.equal(response.json()[1].result,'0x2105');
  assert.equal(bodies.length,2);assert.equal(bodies[0],bodies[1]);const m=await metrics(proxy);assert.equal(m.sourceCallsReserved,4);assert.equal(m.forwardedItems,4);assert.equal(m.sourceReadRecovery.wireAttempts,2);assert.equal(m.sourceReadRecovery.retryAttempts,1);assert.equal(m.sourceReadRecovery.retryResponses,1);
  assert.equal(JSON.stringify(m).includes('RAW_SECRET_SENTINEL'),false);
 });
});
test('production proxy never retries HTTP, RPC, malformed/correlation or response-body failures',async()=>{
 for(const variant of ['http','rpc','json','correlation','body'])await fixture((req,res)=>{
  if(variant==='http'){res.statusCode=503;res.end('RAW_SECRET_SENTINEL');return;}
  if(variant==='body'){res.writeHead(200,{'content-type':'application/json','content-length':'1024'});res.flushHeaders();res.write('{');setTimeout(()=>res.destroy(),5);return;}
  res.end(variant==='json'?'RAW_SECRET_SENTINEL':JSON.stringify(variant==='rpc'?{jsonrpc:'2.0',id:1,error:{code:-32000,message:'RAW_SECRET_SENTINEL'}}:{jsonrpc:'2.0',id:2,result:'0x2105'}));
 },async(proxy,bodies)=>{await proxy.inject({method:'POST',url:'/',payload:request()});assert.equal(bodies.length,1,variant);const m=await metrics(proxy);assert.equal(m.sourceCallsReserved,1);assert.equal(m.sourceReadRecovery.retryAttempts,0);});
});
test('local mode never retries disconnect; forbidden source writes never forward',async()=>{
 await fixture(req=>{req.socket.destroy();},async(proxy,bodies)=>{assert.equal((await proxy.inject({method:'POST',url:'/',payload:request()})).statusCode,502);assert.equal(bodies.length,1);assert.equal((await metrics(proxy)).sourceReadRecovery,null);},true);
 await fixture(()=>{throw Error('forbidden request forwarded');},async(proxy,bodies)=>{
  for(const payload of [{...request(),method:'anvil_reset'},
    {...request(),method:'eth_getBalance',params:[`0x${'1'.repeat(40)}`,'latest']},
    {...request(),method:'eth_getTransactionReceipt',params:[`0x${'1'.repeat(64)}`]}])await proxy.inject({method:'POST',url:'/',payload});
  assert.equal(bodies.length,0);assert.equal((await metrics(proxy)).sourceCallsReserved,0);
 });
});
test('production source cap charges every wire item and blocks whole retry batch at exhaustion',async()=>{
 const {manifest}=await loadManifest();
 for(const lastBatchSize of [1,2]){let disconnect=false;
 await fixture((req,res,body)=>{if(disconnect){req.socket.destroy();return;}const input=JSON.parse(body),reply=(r:{id:number})=>({jsonrpc:'2.0',id:r.id,result:'0x2105'});res.end(JSON.stringify(Array.isArray(input)?input.map(reply):reply(input)));},async(proxy,bodies)=>{
  let remaining=manifest.guardrails.maxSourceCallsPerTrial-(lastBatchSize===1?1:3);
  while(remaining){const n=Math.min(remaining,manifest.source.maxBatchItems);await proxy.inject({method:'POST',url:'/',payload:Array.from({length:n},(_,i)=>request(i+1))});remaining-=n;}
  disconnect=true;const before=bodies.length;assert.equal((await proxy.inject({method:'POST',url:'/',payload:Array.from({length:lastBatchSize},(_,i)=>request(i+1))})).statusCode,502);
  assert.equal(bodies.length,before+1);const m=await metrics(proxy);assert.equal(m.sourceCallsReserved,manifest.guardrails.maxSourceCallsPerTrial-(lastBatchSize===1?0:1));assert.equal(m.sourceReadRecovery.retryBudgetDenied,1);assert.equal(m.sourceReadRecovery.retryAttempts,0);
 });
 }
});
