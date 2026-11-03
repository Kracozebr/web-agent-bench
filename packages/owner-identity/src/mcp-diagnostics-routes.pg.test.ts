import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import Fastify from 'fastify';
import postgres from 'postgres';
import {drizzle} from 'drizzle-orm/postgres-js';
import type {OwnerDatabase} from './db.js';
import type {ReportClosureStateStore} from './report-closure-state.js';
import {HttpError} from './http-error.js';
import {responseError} from './http-error-response.js';
import {addFixture} from './task-run-completion.test-fixture.js';
import {diagnosticHash} from './mcp-diagnostics-contract.js';
import {registerDiagnosticRoutes} from './mcp-diagnostics-routes.js';
import {registerDiagnosticIngress} from './mcp-diagnostics-ingress.js';
import {DIAGNOSTIC_CALLBACK,DIAGNOSTIC_CLIENT_ID,DIAGNOSTIC_SCOPE} from './mcp-diagnostics-oauth.js';
import {createMcpHandler,McpServer} from '@modelcontextprotocol/server';
import {z} from 'zod';
import {decodeDiagnosticWire} from './mcp-diagnostics-wire.js';
import {enforceApiMutationOrigin} from './api-mutation-origin.js';
import {cleanupDiagnosticRetention} from './mcp-diagnostics-service.js';

// AICODE-NOTE: Actual Fastify + disposable PostgreSQL integration. Synthetic
// identity adapters and the rejection handler below do not prove browser, native
// MCP SDK or deployed authorization acceptance. No preserved Google DB writes.
test('diagnostic routes preserve private DTOs, scoped OAuth and ingress evidence in PostgreSQL',
 {skip:process.env.OID_MCP_DIAGNOSTICS_PG_TEST!=='1'},async t=>{
 const source=process.env.OID_DATABASE_URL;assert.ok(source);const sourceUrl=new URL(source);
 assert.equal(sourceUrl.hostname,'postgres');assert.equal(sourceUrl.username,'oid_owner');assert.equal(sourceUrl.pathname,'/owner_identity');
 const name='oid_diagnostics_routes_'+randomUUID().replaceAll('-','');assert.match(name,/^oid_diagnostics_routes_[a-f0-9]{32}$/);
 const uri=new URL(source);uri.pathname='/'+name;const admin=postgres(source,{max:1,connect_timeout:10});
 const client=postgres(uri.href,{max:5,connect_timeout:10}),db=drizzle(client) as unknown as OwnerDatabase;
 const app=Fastify({logger:false});let created=false;
 try{
  await admin.unsafe('CREATE DATABASE '+name);created=true;
  const migrated=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{cwd:'/workspace',env:{PATH:process.env.PATH,HOME:process.env.HOME,NODE_ENV:'test',OID_DATABASE_URL:uri.href,OID_AUTH_SECRET:'synthetic-route-test-only-secret-1234567890123456789',OID_PUBLIC_ORIGIN:'https://bench.example'},encoding:'utf8'});
  assert.equal(migrated.status,0,'disposable diagnostic route schema migration must succeed');
  const f=await addFixture(client,{includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600});
  const foreign=await addFixture(client,{includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600});
  const intentId=(await client`SELECT intent_id FROM oid_benchmark_run WHERE id=${f.runId}`)[0]!.intent_id as string;
  const userId=(await client`SELECT auth_user_id FROM oid_owner WHERE id=${f.ownerId}`)[0]!.auth_user_id as string;
  const sessionId=randomUUID(),connectionId=randomUUID();
  await client`INSERT INTO oid_auth_session(id,user_id,token,expires_at) VALUES (${sessionId},${userId},${randomUUID()},clock_timestamp()+interval '1 day')`;
  await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,access_generation,expires_at,oauth_client_id)
   VALUES (${connectionId},${f.ownerId},${f.agentId},${'diag_routes_'+randomUUID()},'oauth','https://bench.example/api/agent/mcp',1,clock_timestamp()+interval '1 day','synthetic-native-client')`;
  await client`INSERT INTO oid_agent_oauth_authorization(id,operation_id,query_hash,owner_id,auth_user_id,auth_session_id,agent_id,grant_id,client_id,resource,redirect_uri,scopes,authorization_code_hash,access_generation,policy_revision,status,expires_at)
   VALUES (${randomUUID()},${randomUUID()},${randomUUID()},${f.ownerId},${userId},${sessionId},${f.agentId},${connectionId},'synthetic-native-client','https://bench.example/api/agent/mcp','http://127.0.0.1:38765/oauth/callback',ARRAY['agent:operate'],${randomUUID()},1,1,'approved',clock_timestamp()+interval '1 day')`;
  await client`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES (${randomUUID()},'agent.connection.intent_bound',${'connection-intent:'+intentId},${f.ownerId},${JSON.stringify({connectionId,agentId:f.agentId})}::jsonb)`;
  let externalClosure:string|null=null;
  const closure:ReportClosureStateStore={async readAuthoritativeClosure(){return {betaEndedAt:externalClosure,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw new Error('read-only fixture closure');}};
  const service={db,reportClosureState:closure},oauth={db,config:{publicOrigin:'https://bench.example',nodeEnv:'test',authSecret:'synthetic-route-test-only-secret-1234567890123456789',mcpTransportProfile:'remote-oauth-v1' as const}};
  const role=(request:{headers:Record<string,unknown>})=>request.headers['x-fixture-role'];
  app.addHook('onRequest',async request=>enforceApiMutationOrigin(request,'https://bench.example',async r=>{
    if(r.headers.origin!=='https://bench.example')throw new HttpError(403,'FORBIDDEN','Origin rejected');
  }));
  registerDiagnosticRoutes(app,{service,oauth,async resolveOwner(request){if(role(request)==='owner'||role(request)==='admin')return {ownerId:f.ownerId,authSessionId:sessionId};if(role(request)==='foreign')return {ownerId:foreign.ownerId,authSessionId:randomUUID()};throw new HttpError(401,'UNAUTHORIZED','Fixture owner session required');},async requireAdmin(request){if(role(request)!=='admin')throw new HttpError(403,'FORBIDDEN','Fixture administrator required');},async requireOrigin(request){if(request.headers.origin!=='https://bench.example')throw new HttpError(403,'FORBIDDEN','Origin rejected');},async rateLimit(){}});
  const ingress=registerDiagnosticIngress(app,service);
  app.addHook('onRequest',async request=>{if(request.url==='/api/agent/mcp'&&role(request)==='owner')await ingress.authenticated(request,{ownerId:f.ownerId,agentId:f.agentId,connectionId});});
  // Synthetic SDK rejection handler: exercises real ingress persistence without
  // claiming that this handler is the MCP SDK's schema implementation.
  app.post('/api/agent/mcp',async(request,reply)=>{
   if(request.headers['x-fixture-sdk']!=='actual')return reply.code(400).send({jsonrpc:'2.0',id:'synthetic',error:{code:-32602,message:'Synthetic validation rejection'}});
   const handler=createMcpHandler(()=>{
    const server=new McpServer({name:'Actual SDK diagnostic regression',version:'1.0.0'},{supportedProtocolVersions:['2025-06-18']});
    const configuration={inputSchema:z.object({agentId:z.string().uuid().optional(),operationId:z.string().regex(/^[A-Za-z0-9_-]{12,128}$/)})};
    ingress.toolRegistered(request,'identity.preflight',configuration);
    server.registerTool('identity.preflight',configuration,async()=>{ingress.handlerEntered(request);return{content:[{type:'text',text:'{"status":"allowed"}'}]};});return server;
   },{legacy:'stateless',responseMode:'json',keepAliveMs:0});
   try{
    const response=await handler.fetch(new Request('https://bench.example/api/agent/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify(request.body)}),{parsedBody:request.body});
    response.headers.forEach((value,key)=>reply.header(key,value));return reply.code(response.status).send(Buffer.from(await response.arrayBuffer()));
   }finally{await handler.close();}
  });
  app.setErrorHandler((error,_request,reply)=>{if((error as {code?:string}).code==='FST_ERR_CTP_INVALID_JSON_BODY')return reply.code(400).send({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Malformed JSON'}});return responseError(reply,error);});
  await app.ready();
  const ownerHeaders={'x-fixture-role':'owner',origin:'https://bench.example'};
  const snapshot=async()=>JSON.stringify(await client`SELECT (SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_benchmark_run r) AS runs,(SELECT md5(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY id),'')) FROM oid_ledger_entry r) AS ledger,(SELECT count(*) FROM oid_run_task_action) AS actions`);
  const original=await snapshot();let accessToken='',caseId='';let fallbackPayload:Record<string,unknown>={};
  async function observeTrace(trace: string | number | string[] | undefined, predicate:(rows:postgres.RowList<postgres.Row[]>)=>boolean) {
   assert.equal(typeof trace,'string');
   for(let attempt=0;attempt<20;attempt++){
    const records=await client`SELECT stage,outcome,error_code,envelope FROM oid_mcp_diagnostic_event WHERE trace_id=${String(trace)}`;
    if(predicate(records))return records;
    await delay(50);
   }
   assert.fail('bounded diagnostic observer poll expired');
  }
  await t.test('separate PKCE consent produces a real scoped helper token through routes',async()=>{
   const verifier='synthetic-route-verifier-123456789012345678901234567890',challenge=createHash('sha256').update(verifier).digest('base64url');
   const resource='https://bench.example/api/diagnostics';
   const query=new URLSearchParams({client_id:DIAGNOSTIC_CLIENT_ID,redirect_uri:DIAGNOSTIC_CALLBACK,response_type:'code',code_challenge_method:'S256',code_challenge:challenge,state:'synthetic-route-state-1234567890',scope:DIAGNOSTIC_SCOPE,resource});
   const begin=await app.inject({method:'GET',url:'/api/diagnostics/oauth/authorize?'+query});assert.equal(begin.statusCode,302);
   const requestId=new URL(begin.headers.location!,'https://bench.example').searchParams.get('requestId')!;
   const view=await app.inject({method:'GET',url:'/api/owner/diagnostics/oauth/requests/'+requestId,headers:ownerHeaders});assert.equal(view.statusCode,200);assert.ok(view.json().agents.some((a:{agentId:string})=>a.agentId===f.agentId));
   const consent=await app.inject({method:'POST',url:'/api/diagnostics/oauth/consent',headers:ownerHeaders,payload:{requestId,operationId:'synthetic_route_consent',approved:true,agentId:f.agentId,connectionId}});assert.equal(consent.statusCode,200);
   const code=new URL(consent.json().redirectUrl).searchParams.get('code')!;
   const token=await app.inject({method:'POST',url:'/api/diagnostics/oauth/token',payload:{grant_type:'authorization_code',client_id:DIAGNOSTIC_CLIENT_ID,redirect_uri:DIAGNOSTIC_CALLBACK,resource,scope:DIAGNOSTIC_SCOPE,code,code_verifier:verifier}});assert.equal(token.statusCode,200);accessToken=token.json().access_token;assert.match(accessToken,/^mcd_a_/);
   const register=await app.inject({method:'POST',url:'/api/diagnostics/cases',headers:{authorization:'Bearer '+accessToken},payload:{diagnosticSessionId:randomUUID(),intentId}});assert.equal(register.statusCode,200);caseId=register.json().caseId;assert.ok(caseId);
  });
  await t.test('shared server Origin guard permits helper protocol but protects browser mutations',async()=>{
   const before=Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case`)[0]!.n);
   for(const url of ['/api/diagnostics/oauth/token','/api/diagnostics/cases',`/api/diagnostics/cases/${randomUUID()}/batches`]){
    const denied=await app.inject({method:'POST',url,headers:{origin:'https://foreign.example',authorization:'Bearer '+accessToken},payload:{}});
    assert.equal(denied.statusCode,403,'a supplied foreign Origin must be rejected before protocol handling');
   }
   for(const url of ['/api/diagnostics/oauth/consent','/api/owner/diagnostics/import','/api/diagnostics/unregistered']){
    const denied=await app.inject({method:'POST',url,headers:{'x-fixture-role':'owner',authorization:'Bearer '+accessToken},payload:{}});
    assert.equal(denied.statusCode,403,'cookie-based and unregistered mutations still require same Origin');
   }
   const unauthenticated=await app.inject({method:'POST',url:'/api/diagnostics/cases',payload:{}});
   assert.equal(unauthenticated.statusCode,401,'Origin exemption cannot provide helper authority');
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case`)[0]!.n),before);
   assert.equal(await snapshot(),original);
  });
  await t.test('helper upload persists original batch and private list DTO stays flat',async()=>{
   assert.ok(caseId);const event={eventId:randomUUID(),source:'client',stage:'client_validation',tool:'identity.preflight',outcome:'error',errorCode:'INPUT_VALIDATION_ERROR',startedAt:'2026-11-02T00:00:00.000Z',completedAt:'2026-11-02T00:00:00.001Z',durationMs:1};
   const body={segmentId:randomUUID(),batchSequence:0,events:[event],completion:'complete'};
   fallbackPayload={diagnosticSessionId:randomUUID(),intentId,caseId,batch:{...body,payloadHash:diagnosticHash(body)}};
   const upload=await app.inject({method:'POST',url:`/api/diagnostics/cases/${caseId}/batches`,headers:{authorization:'Bearer '+accessToken},payload:{...body,payloadHash:diagnosticHash(body)}});assert.equal(upload.statusCode,200);assert.equal(upload.json().highestContiguousSequence,0);assert.equal(upload.json().reportCreated,true);
   const list=await app.inject({method:'GET',url:'/api/owner/diagnostics/cases',headers:ownerHeaders});assert.equal(list.statusCode,200);assert.ok(Array.isArray(list.json().cases));assert.ok(list.json().cases.some((c:{caseId:string})=>c.caseId===caseId));
   const detail=await app.inject({method:'GET',url:`/api/owner/diagnostics/cases/${caseId}`,headers:ownerHeaders});assert.equal(detail.statusCode,200);assert.equal(detail.json().events[0].responsibility,'unknown');assert.equal(detail.json().case.sourceTrust,'client_observed_unverified');
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_support_report r JOIN oid_mcp_diagnostic_case c ON c.report_id=r.id WHERE c.id=${caseId}`)[0]!.n),1);
  });
  await t.test('foreign, anonymous and task credentials cannot read or import owned diagnostics',async()=>{
   assert.ok(caseId);
   for(const headers of [{},{authorization:'Bearer synthetic-task-token'},{authorization:'Bearer '+accessToken}]){
    assert.equal((await app.inject({method:'GET',url:`/api/owner/diagnostics/cases/${caseId}`,headers})).statusCode,401);
    assert.equal((await app.inject({method:'GET',url:'/api/admin/diagnostics/cases',headers})).statusCode,403);
   }
   assert.equal((await app.inject({method:'GET',url:`/api/owner/diagnostics/cases/${caseId}`,headers:{'x-fixture-role':'foreign'}})).statusCode,404);
   assert.equal((await app.inject({method:'GET',url:'/api/admin/diagnostics/cases',headers:ownerHeaders})).statusCode,403);
   const adminList=await app.inject({method:'GET',url:'/api/admin/diagnostics/cases',headers:{'x-fixture-role':'admin'}});assert.equal(adminList.statusCode,200);assert.ok(Array.isArray(adminList.json().cases));
   assert.equal((await app.inject({method:'POST',url:'/api/owner/diagnostics/import',headers:{origin:'https://bench.example',authorization:'Bearer '+accessToken},payload:{}})).statusCode,401);
   const before=Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_batch`)[0]!.n);
   assert.equal((await app.inject({method:'POST',url:'/api/owner/diagnostics/import',headers:{'x-fixture-role':'foreign',origin:'https://bench.example'},payload:fallbackPayload})).statusCode,404);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_batch`)[0]!.n),before);
   const replay=await app.inject({method:'POST',url:'/api/owner/diagnostics/import',headers:ownerHeaders,payload:fallbackPayload});assert.equal(replay.statusCode,200);assert.equal(replay.json().highestContiguousSequence,0);
  });
  await t.test('actual JSON parse rejection and synthetic SDK rejection retain safe trace and stage',async()=>{
   const malformed=await app.inject({method:'POST',url:'/api/agent/mcp',headers:{'content-type':'application/json'},payload:'{malformed'});assert.equal(malformed.statusCode,400);
   const malformedTrace=malformed.headers['x-w3bench-diagnostic-trace'];assert.ok(malformedTrace);
   const parseRows=await observeTrace(malformedTrace,records=>records.some(e=>e.stage==='ingress'&&e.outcome==='error'));
   assert.ok(parseRows.some(e=>e.stage==='ingress'&&e.outcome==='error'),'parse failure must be ingress error');
   const rejected=await app.inject({method:'POST',url:'/api/agent/mcp',headers:{...ownerHeaders,'x-w3bench-diagnostic-case':caseId},payload:{jsonrpc:'2.0',id:'synthetic',method:'tools/call',params:{name:'identity.preflight',arguments:{agentId:'synthetic-canary-invalid-value'}}}});assert.equal(rejected.statusCode,400);
   const trace=rejected.headers['x-w3bench-diagnostic-trace'];assert.ok(trace);
   const observed=await observeTrace(trace,records=>records.some(e=>e.stage==='sdk_validation'&&e.outcome==='error'));
   assert.ok(observed.some(e=>e.stage==='sdk_validation'&&e.outcome==='error'&&e.error_code==='INPUT_VALIDATION_ERROR'));
   assert.equal(observed.filter(e=>e.stage==='authentication'&&e.outcome==='error').length,0,'successful authentication cannot inherit validation failure');
   assert.ok(observed.every(e=>!JSON.stringify(e.envelope).includes('synthetic-canary-invalid-value')));
   assert.equal(await snapshot(),original);
  });
  await t.test('actual SDK HTTP200 SSE validation error preserves trace metadata and durable error stage',async()=>{
   const id=randomUUID();const rejected=await app.inject({method:'POST',url:'/api/agent/mcp',headers:{...ownerHeaders,'x-fixture-sdk':'actual','x-w3bench-diagnostic-case':caseId},payload:{jsonrpc:'2.0',id,method:'tools/call',params:{name:'identity.preflight',arguments:{operationId:'bad'}}}});
   assert.equal(rejected.statusCode,200);assert.match(String(rejected.headers['content-type']),/text\/event-stream/);
   const wire=decodeDiagnosticWire(rejected.payload,String(rejected.headers['content-type'])),response=wire.messages.find(message=>message.id===id)!;
   assert.equal((response.result as {isError:boolean}).isError,true);
   const meta=(response.result as {_meta:Record<string,{traceId:string;errorCode:string;fieldPaths:string[];schemaHash:string}>})._meta['w3bench/diagnostics']!;
   assert.equal(meta.traceId,rejected.headers['x-w3bench-diagnostic-trace']);assert.equal(meta.errorCode,'INPUT_VALIDATION_ERROR');assert.deepEqual(meta.fieldPaths,['operationId']);assert.match(meta.schemaHash,/^[a-f0-9]{64}$/);
   const rows=await observeTrace(meta.traceId,records=>records.some(e=>e.stage==='sdk_validation'&&e.outcome==='error'));
   assert.equal(rows.filter(e=>e.stage==='sdk_validation'&&e.error_code==='INPUT_VALIDATION_ERROR').length,1);
   assert.equal(rows.filter(e=>e.stage==='authentication'&&e.outcome==='error').length,0);assert.equal(await snapshot(),original);
  });
  await t.test('forged case header is rejected before the handler and cannot mutate business state',async()=>{
   const rejected=await app.inject({method:'POST',url:'/api/agent/mcp',headers:{...ownerHeaders,'x-w3bench-diagnostic-case':randomUUID()},payload:{jsonrpc:'2.0',id:'synthetic',method:'tools/call',params:{name:'identity.preflight',arguments:{}}}});
   assert.equal(rejected.statusCode,404);assert.equal(await snapshot(),original);
   const malformed=await app.inject({method:'POST',url:'/api/agent/mcp',headers:{...ownerHeaders,'x-w3bench-diagnostic-case':'synthetic-invalid-reference'},payload:{jsonrpc:'2.0',id:'synthetic',method:'tools/call',params:{name:'identity.preflight',arguments:{}}}});
   assert.equal(malformed.statusCode,400);assert.equal(await snapshot(),original);
  });
  await t.test('revoked helper authorization leaves no new report writes',async()=>{
   const before=Number((await client`SELECT count(*) AS n FROM oid_support_report`)[0]!.n);
   await client`UPDATE oid_diagnostic_oauth_grant SET revoked_at=clock_timestamp() WHERE connection_id=${connectionId}`;
   const denied=await app.inject({method:'POST',url:'/api/diagnostics/cases',headers:{authorization:'Bearer '+accessToken},payload:{diagnosticSessionId:randomUUID()}});assert.equal(denied.statusCode,401);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_support_report`)[0]!.n),before);assert.equal(await snapshot(),original);
  });
  await t.test('original owned export remains retention-expired after cleanup deletes its case, without an existence oracle',async()=>{
   const diagnosticSessionId=randomUUID(),binding={agentId:f.agentId,connectionId},at=new Date().toISOString();
   const batch={segmentId:randomUUID(),batchSequence:0,events:[{eventId:randomUUID(),source:'client',stage:'client_validation',tool:'identity.preflight',outcome:'error',errorCode:'INPUT_VALIDATION_ERROR',startedAt:at,completedAt:at,durationMs:0}],completion:'partial'};
   const exported={diagnosticSessionId,binding,batch:{...batch,payloadHash:diagnosticHash(batch)}};
   const send=(payload:unknown,headers:Record<string,string>=ownerHeaders)=>app.inject({method:'POST',url:'/api/owner/diagnostics/import',headers,payload:payload as Record<string,unknown>});
   const first=await send(exported);assert.equal(first.statusCode,200);const originalExport={...exported,caseId:first.json().caseId};assert.ok(originalExport.caseId);
   assert.equal((await send(originalExport)).statusCode,200,'the exact original session/binding must replay before expiry');
   assert.equal((await send({...originalExport,diagnosticSessionId:randomUUID()})).statusCode,409,'a mismatched original session is not a valid stale-export test');
   assert.equal((await send({...originalExport,binding:{...binding,agentId:randomUUID()}})).statusCode,404);
   assert.equal((await send(originalExport,{'x-fixture-role':'foreign',origin:'https://bench.example'})).statusCode,404);
   // Hold the case relation so import pauses between its retention check and
   // metadata read. Cleanup must wait on that same import's retained SHARE row
   // lock, rather than deleting the case in an unlocked gap between the two.
   const held=await client.reserve();let importing:ReturnType<typeof send>|undefined,cleaning:ReturnType<typeof cleanupDiagnosticRetention>|undefined,heldTransaction=false;
   try{
    await held`BEGIN`;heldTransaction=true;await held`LOCK TABLE oid_mcp_diagnostic_case IN ACCESS EXCLUSIVE MODE`;
    importing=send(originalExport);importing.catch(()=>{});let importPid:number|undefined;
    for(let i=0;i<80&&!importPid;i++){const waits=await client`SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
      WHERE a.datname=current_database() AND a.usename=current_user AND NOT l.granted AND l.relation='oid_mcp_diagnostic_case'::regclass
      AND l.mode='AccessShareLock' AND a.query LIKE '%SELECT agent_id,connection_id,intent_id,diagnostic_session_id%'`;importPid=waits[0]?.pid as number|undefined;if(!importPid)await delay(20);}
    assert.ok(importPid,'actual import must pause at its case metadata lookup');
    externalClosure=new Date(Date.now()-31*24*60*60*1000).toISOString();cleaning=cleanupDiagnosticRetention(service);cleaning.catch(()=>{});let blockedByImport=false;
    for(let i=0;i<80&&!blockedByImport;i++){const blocked=await client`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=current_database() AND ${importPid}=ANY(pg_blocking_pids(pid))`;blockedByImport=Number(blocked[0]!.n)>0;if(!blockedByImport)await delay(20);}
    assert.ok(blockedByImport,'retention SHARE must remain held through the case metadata read');
    await held`COMMIT`;heldTransaction=false;const [response,cleaned]=await Promise.all([importing,cleaning]);assert.equal(response.statusCode,410,'the subsequent registration must recheck the newly expired authority');
    assert.equal(cleaned.expired,true);assert.ok(cleaned.removedCases>0);assert.ok(cleaned.removedEvents>0);
   }finally{if(heldTransaction)await held`ROLLBACK`.catch(()=>{});held.release();await Promise.allSettled([importing,cleaning].filter(Boolean));}
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case WHERE id=${originalExport.caseId}`)[0]!.n),0);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_retention_receipt`)[0]!.n),1);
   const checkExpired=async(phase:string,payload:unknown,headers:Record<string,string>=ownerHeaders)=>{
    const response=await send(payload,headers),observed={phase,httpStatus:response.statusCode,errorCode:response.json().error?.code};
    assert.equal(observed.httpStatus,410,JSON.stringify(observed));assert.equal(observed.errorCode,'REPORT_RETENTION_EXPIRED');
   };
   await checkExpired('original_stale_export_after_cleanup',originalExport);
   await checkExpired('fresh_valid_import_without_case',{...exported,diagnosticSessionId:randomUUID()});
   await checkExpired('missing_case_has_same_global_expiry',{...originalExport,caseId:randomUUID()});
   await checkExpired('authenticated_foreign_owner_has_same_global_expiry',originalExport,{'x-fixture-role':'foreign',origin:'https://bench.example'});
   for(const headers of [{origin:'https://bench.example'},{origin:'https://bench.example',authorization:'Bearer '+accessToken}]){
    assert.equal((await send(originalExport,headers)).statusCode,401,'authentication must precede expired-import handling');
   }
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_case`)[0]!.n),0);
   assert.equal(Number((await client`SELECT count(*) AS n FROM oid_mcp_diagnostic_event`)[0]!.n),0);assert.equal(await snapshot(),original);
  });
 }finally{await app.close();await client.end();if(created)await admin.unsafe('DROP DATABASE '+name+' WITH (FORCE)');await admin.end();}
});
