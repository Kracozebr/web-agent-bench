/** Controlled reference-SDK causal verification, never attribution of a native Codex failure. */
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
import {relative,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {readMcdWireResponse} from './mcp-diagnostics-wire.mjs';

const requireOwner=createRequire(new URL('../../owner-identity/package.json',import.meta.url));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const publicOperation={value:'synthetic-control-value'};
const profile={implementation:'mcd_controlled_reference_sdk',clientPackage:'@modelcontextprotocol/client',version:'2.4.0',nativeClient:false};

async function sourceRef(repoRoot,path){const file=resolve(repoRoot,path),bytes=await readFile(file);return {path:relative(repoRoot,file).split(sep).join('/'),sha256:digest(bytes)};}

async function fixture(){
  const [{default:Fastify},{createMcpHandler,McpServer},{z}]=await Promise.all([import(pathToFileURL(requireOwner.resolve('fastify')).href),import(pathToFileURL(requireOwner.resolve('@modelcontextprotocol/server')).href),import(pathToFileURL(requireOwner.resolve('zod')).href)]);
  const dependency=Fastify({logger:false});dependency.get('/synthetic-dependency',async(_request,reply)=>reply.code(503).send({error:{code:'SYNTHETIC_DEPENDENCY_FAILURE'}}));const dependencyOrigin=await dependency.listen({host:'127.0.0.1',port:0});
  const app=Fastify({logger:false});let mode='normal',dependencyObservations=[],serverObservations=[];
  app.post('/mcp',async(request,reply)=>{
    const handler=createMcpHandler(()=>{const server=new McpServer({name:'MCD controlled reference fixture',version:'1.0.0'},{supportedProtocolVersions:['2025-06-18','2026-07-28']});
      server.registerTool('mcd_probe',{inputSchema:z.object({value:mode==='platform_contract'?z.number().int():z.string().min(1)}).strict()},async()=>{
        const callIdHash=digest(String(request.body?.id));serverObservations.push({phase:'handler_entered',mode,callIdHash});
        if(mode==='platform_runtime'){serverObservations.push({phase:'handler_throw',mode,callIdHash,exceptionType:'Error'});throw new Error('synthetic_reference_handler_exception');}
        if(mode==='external_dependency'){
          const response=await fetch(dependencyOrigin+'/synthetic-dependency',{signal:AbortSignal.timeout(2000)});dependencyObservations.push({method:'GET',path:'/synthetic-dependency',httpStatus:response.status});await response.body?.cancel();if(!response.ok)throw new Error('synthetic_reference_dependency_exception');
        }
        if(mode==='expected_policy_denial'){serverObservations.push({phase:'policy_deny',mode,callIdHash,ruleId:'synthetic_reference_policy'});return {isError:true,content:[{type:'text',text:JSON.stringify({error:{code:'FORBIDDEN'}})}]};}
        return {content:[{type:'text',text:JSON.stringify({status:'ok'})}],structuredContent:{status:'ok'}};
      });return server;
    },{legacy:'stateless',responseMode:'json',keepAliveMs:0});
    const headers=new Headers({'content-type':'application/json',accept:'application/json, text/event-stream'});if(request.headers['mcp-protocol-version'])headers.set('mcp-protocol-version',request.headers['mcp-protocol-version']);
    const response=await handler.fetch(new Request(origin+'/mcp',{method:'POST',headers,body:JSON.stringify(request.body)}),{parsedBody:request.body});
    response.headers.forEach((v,k)=>reply.header(k,v));return reply.code(response.status).send(Buffer.from(await response.arrayBuffer()));
  });const origin=await app.listen({host:'127.0.0.1',port:0});
  return {async probe(kind){mode=kind;dependencyObservations=[];serverObservations=[];const wire=[];const client=new Client({name:'MCD reference SDK client',version:'1.0.0'});const transport=new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{fetch:async(url,init)=>{const response=await fetch(url,init);let requestBody;try{requestBody=JSON.parse(init?.body??'null');}catch{}const decoded=await readMcdWireResponse(response.clone());const responseBody=decoded.value;wire.push({method:requestBody?.method??'unknown',callIdHash:digest(String(requestBody?.id)),httpStatus:response.status,framing:decoded.proof,...(responseBody?.error?{rpcErrorCode:responseBody.error.code}:{}),...(responseBody?.result?.isError?{toolError:true}:{})});return response;}});
      let schema,result,exception;
      try{await client.connect(transport);const tools=await client.listTools();schema=tools.tools.find(t=>t.name==='mcd_probe')?.inputSchema;assert(schema);try{result=await client.callTool({name:'mcd_probe',arguments:kind==='client_contract'?{value:7}:publicOperation});if(kind==='client_runtime'){assert.equal(result.isError,undefined);assert.equal(result.structuredContent?.status,'ok');throw new TypeError('synthetic_reference_client_exception_after_valid_response');}}catch(error){exception={name:error.name,...(typeof error.code==='number'?{rpcCode:error.code}:{})};}}
      finally{await client.close().catch(()=>{});}
      return {schema,result:result?{isError:result.isError===true,status:result.structuredContent?.status??null}:null,exception,wire,dependencyObservations:[...dependencyObservations],serverObservations:[...serverObservations]};
    },async close(){await app.close();await dependency.close();}};
}

function factsFor(kind,probe){
  const call=probe.wire.filter(e=>e.method==='tools/call');assert.equal(call.length,1);const response=call[0];
  if(kind==='client_contract'){assert(probe.exception||response.rpcErrorCode===-32602||probe.result?.isError);return {serverValidationRejected:true,compatibilityVerified:true,schemaCompatible:true,violationMatchesPins:true};}
  if(kind==='platform_contract'){assert.equal(probe.schema.properties.value.type,'integer');assert(probe.exception||response.rpcErrorCode===-32602||probe.result?.isError);return {compatibilityVerified:true,issuedOperationUnrepresentable:true};}
  if(kind==='client_runtime'){assert.equal(probe.exception?.name,'TypeError');assert.equal(probe.result?.status,'ok');assert.equal(probe.dependencyObservations.length,0);return {clientExceptionReproduced:true,matchingValidServerResponse:true};}
  if(kind==='platform_runtime'){assert(probe.result?.isError||probe.exception);assert.equal(probe.dependencyObservations.length,0);return {serverFailure:true,dependencyCauseExcluded:true};}
  if(kind==='external_dependency'){assert.deepEqual(probe.dependencyObservations,[{method:'GET',path:'/synthetic-dependency',httpStatus:503}]);assert(probe.result?.isError||probe.exception);return {dependencyFailure:true,competingCausesExcluded:true};}
  if(kind==='expected_policy_denial'){assert.equal(probe.result?.isError,true);assert.equal(probe.dependencyObservations.length,0);return {policyMatched:true};}
  throw new Error('mcd_unrecognized_reference_control');
}

/** Transport smoke only; it supplies no database, browser or native acceptance. */
export async function qualifyMcdReferenceSdk(){
  const control=await fixture(),results=[];
  try{for(const category of ['client_contract','platform_contract','client_runtime','platform_runtime','external_dependency','expected_policy_denial']){
    const probe=await control.probe(category);factsFor(category,probe);results.push({category,httpCalls:probe.wire.length,toolCalls:probe.wire.filter(e=>e.method==='tools/call').length,clientException:probe.exception?.name??null,wire:probe.wire.filter(e=>e.method==='tools/call').map(e=>({httpStatus:e.httpStatus,...e.framing}))});
  }return {profile,results};}finally{await control.close();}
}

/** Exact real SDK invalid-preflight framing probe; response text stays private. */
export async function probeMcdSdkValidationWire(){
  const [{default:Fastify},{createMcpHandler,McpServer},{z}]=await Promise.all([import(pathToFileURL(requireOwner.resolve('fastify')).href),import(pathToFileURL(requireOwner.resolve('@modelcontextprotocol/server')).href),import(pathToFileURL(requireOwner.resolve('zod')).href)]);
  const app=Fastify({logger:false});let handlerEntered=false;
  app.post('/mcp',async(request,reply)=>{
    const handler=createMcpHandler(()=>{const server=new McpServer({name:'MCD invalid preflight reference',version:'1.0.0'},{supportedProtocolVersions:['2025-06-18','2026-07-28']});server.registerTool('identity.preflight',{inputSchema:z.object({agentId:z.string().uuid().optional(),operationId:z.string().regex(/^[A-Za-z0-9_-]{12,128}$/)})},async()=>{handlerEntered=true;return {content:[{type:'text',text:'synthetic allowed'}]};});return server;},{legacy:'stateless',responseMode:'json',keepAliveMs:0});
    const response=await handler.fetch(new Request(origin+'/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify(request.body)}),{parsedBody:request.body});response.headers.forEach((v,k)=>reply.header(k,v));return reply.code(response.status).send(Buffer.from(await response.arrayBuffer()));
  });const origin=await app.listen({host:'127.0.0.1',port:0});
  try{const response=await fetch(origin+'/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify({jsonrpc:'2.0',id:randomUUID(),method:'tools/call',params:{name:'identity.preflight',arguments:{operationId:'bad'}}}),signal:AbortSignal.timeout(5000)});const decoded=await readMcdWireResponse(response);return {boundary:'actual_official_sdk_loopback_http',configuration:{legacy:'stateless',responseMode:'json',keepAliveMs:0},httpStatus:response.status,handlerEntered,...decoded.proof};}finally{await app.close();}
}

export async function captureMcdClassificationControls(input){
  const {observer,writer,connection,binding,captureMcdVariant,importMcdBundleThroughUi}=input;
  const [{createDatabase},service]=await Promise.all([import('../../owner-identity/dist/db.js'),import('../../owner-identity/dist/mcp-diagnostics-service.js')]);
  const {client,db}=createDatabase({databaseUrl:input.databaseUrl});const control=await fixture(),variants=[],controls=[];
  try{
    const own=await importMcdBundleThroughUi({page:input.ownerPage,binding});const caseId=own.receipt.caseId;
    const principal={ownerId:input.ownerId,...binding};
    const deps={db,reportClosureState:{async readAuthoritativeClosure(){return {betaEndedAt:null,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw new Error('reference verifier cannot change beta closure');}}};
    const verifierSource=await sourceRef(input.repoRoot,'packages/owner-acceptance/src/mcp-diagnostics-classification.mjs');
    for(const category of ['client_contract','platform_contract','client_runtime','platform_runtime','external_dependency','expected_policy_denial']){
      const name='positive_'+category;let complete;
      variants.push(await captureMcdVariant({name,request:{method:'POST',path:'/mcp',qualification:profile},observer,writer,execute:async()=>{
        const probe=await control.probe(category),causalFacts=factsFor(category,probe);
        const observation={observer:{role:'qualified_client_reproducer',readOnly:true},profile,verifierSource,wire:probe.wire,clientResult:probe.result,clientException:probe.exception??null,dependencyObservations:probe.dependencyObservations,serverObservations:probe.serverObservations};
        const evidenceRef=await writer.write(name+'-causal-observation',observation);const facts={...causalFacts,independentlyVerified:true,evidenceIds:[evidenceRef.sha256]};
        const eventId=randomUUID(),at=new Date().toISOString();await service.recordServerDiagnostic(deps,{principal,caseId,event:{eventId,source:'server',stage:category==='client_contract'||category==='platform_contract'?'sdk_validation':'handler',tool:'unknown',outcome:'error',errorCode:category==='expected_policy_denial'?'FORBIDDEN':'INTERNAL_ERROR',startedAt:at,completedAt:at,durationMs:0},evidence:facts});
        const snapshot=await observer.waitFor(s=>s.events.some(e=>e.eventId===eventId));const projection=snapshot.events.find(e=>e.eventId===eventId);assert.equal(projection.responsibility,category);
        complete={name,facts,projection:{responsibility:projection.responsibility,evidenceIds:projection.evidenceIds},evidenceReferences:[evidenceRef]};
        if(category==='client_contract'||category==='platform_contract'){
          complete.issuedSchemaRef=await writer.write(name+'-issued-schema',probe.schema);complete.issuedContractRef=await writer.write(name+'-issued-contract',{tool:'mcd_probe',requiredOperation:publicOperation,qualification:profile,verifierSource});
          if(category==='client_contract')complete.clientArguments={value:7};
        }
        return {httpStatus:200,eventId,qualification:profile};
      }}));controls.push(complete);
    }
    variants.push(await captureMcdVariant({name:'contradictory_or_missing_evidence',request:{method:'POST',path:'/mcp',qualification:profile},observer,writer,execute:async()=>{
      const response=await control.probe('normal');assert.equal(response.result?.status,'ok');const evidenceRef=await writer.write('missing-evidence-control',{observer:{role:'qualified_client_reproducer',readOnly:true},profile,verifierSource,wire:response.wire,clientResult:response.result,clientException:null,dependencyObservations:response.dependencyObservations,serverObservations:response.serverObservations});
      const facts={independentlyVerified:false,evidenceIds:[evidenceRef.sha256]},eventId=randomUUID(),at=new Date().toISOString();await service.recordServerDiagnostic(deps,{principal,caseId,event:{eventId,source:'server',stage:'transport',tool:'unknown',outcome:'unknown',startedAt:at,completedAt:at,durationMs:0},evidence:facts});
      const snapshot=await observer.waitFor(s=>s.events.some(e=>e.eventId===eventId)),projection=snapshot.events.find(e=>e.eventId===eventId);assert.equal(projection.responsibility,'unknown');controls.push({name:'contradictory_or_missing_evidence',facts,projection:{responsibility:projection.responsibility,evidenceIds:projection.evidenceIds},evidenceReferences:[evidenceRef]});return {httpStatus:200,eventId,qualification:profile};
    }}));
    const allUnknownMutation=controls.filter(c=>c.name.startsWith('positive_')).map(c=>({name:c.name,responsibility:'unknown',evidenceIds:c.projection.evidenceIds}));
    variants.push(await captureMcdVariant({name:'all_unknown_projection_mutation',request:{method:'LOCAL_READONLY_MUTATION',path:'qualified-projection-control'},observer,writer,execute:async()=>({httpStatus:200,mutationReference:await writer.write('all-unknown-untrusted-projection',allUnknownMutation),qualification:profile})}));
    return {variants,raw:{classification:await writer.write('classification',{qualification:profile,verifierSource,controls,allUnknownMutation})}};
  }finally{await control.close();await client.end();}
}
