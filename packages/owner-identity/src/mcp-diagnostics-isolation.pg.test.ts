import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import postgres from 'postgres';
import Fastify from 'fastify';
import {createMcpHandler,McpServer} from '@modelcontextprotocol/server';
import {z} from 'zod';
import {createDatabase,createDiagnosticDatabase} from './db.js';
import type {OwnerIdentityConfig} from './config.js';
import type {ReportClosureStateStore} from './report-closure-state.js';
import {addFixture} from './task-run-completion.test-fixture.js';
import {registerDiagnosticCase,recordServerDiagnostic} from './mcp-diagnostics-service.js';
import {registerDiagnosticIngress} from './mcp-diagnostics-ingress.js';
import {captureDiagnosticWork,setDiagnosticActionSink} from './mcp-diagnostics-boundary.js';
import {admitTaskAction} from './task-action-service.js';
import {completeKnownTrainingRun} from './task-run-completion.js';
import {decodeDiagnosticWire} from './mcp-diagnostics-wire.js';

// AICODE-NOTE: Real PostgreSQL lock/pool and Fastify + MCP SDK boundary. The
// fixture principal is trusted only for this disposable DB; not OAuth acceptance.
test('held diagnostic advisory lock cannot starve real MCP admission or normal completion',
 {skip:process.env.OID_MCP_DIAGNOSTICS_PG_TEST!=='1',timeout:60000},async()=>{
 const source=process.env.OID_DATABASE_URL;assert.ok(source);const checked=new URL(source);
 assert.equal(checked.hostname,'postgres');assert.equal(checked.username,'oid_owner');assert.equal(checked.pathname,'/owner_identity');
 const name='oid_mcd_isolation_'+randomUUID().replaceAll('-','');assert.match(name,/^oid_mcd_isolation_[a-f0-9]{32}$/);
 const url=new URL(source);url.pathname='/'+name;const admin=postgres(source,{max:1,connect_timeout:10});
 const config={databaseUrl:url.href} as OwnerIdentityConfig,main=createDatabase(config),diagnostics=createDiagnosticDatabase(config);
 const observer=postgres(url.href,{max:1,connect_timeout:5}),locker=postgres(url.href,{max:1,connect_timeout:5});
 const app=Fastify({logger:false});let created=false,lockHeld=false;let lock:Awaited<ReturnType<typeof locker.reserve>>|undefined;let businessWork:Promise<unknown>|undefined;let oldSharedWrites:Promise<unknown>[]=[];let oldQueuedProbe:Promise<unknown>|undefined;
 const closure:ReportClosureStateStore={async readAuthoritativeClosure(){return {betaEndedAt:null,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw new Error('fixture closure is read-only');}};
 try{
  await admin.unsafe('CREATE DATABASE '+name);created=true;
  const migrated=spawnSync('pnpm',['--filter','@web-agent-bench/owner-identity','migrate'],{cwd:'/workspace',encoding:'utf8',env:{PATH:process.env.PATH,HOME:process.env.HOME,NODE_ENV:'test',OID_DATABASE_URL:url.href,OID_AUTH_SECRET:'synthetic-isolation-secret-only-1234567890123456789',OID_PUBLIC_ORIGIN:'https://bench.example'}});
  assert.equal(migrated.status,0,'disposable isolation schema migration must succeed');
  const f=await addFixture(main.client,{actionOpen:true,includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:600});
  const completion=await addFixture(main.client,{overallDeadlinePast:true});
  const connectionId=randomUUID(),resource='https://bench.example/api/agent/mcp';
  await main.client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,access_generation,expires_at) VALUES(${connectionId},${f.ownerId},${f.agentId},${randomUUID()},'oauth',${resource},1,clock_timestamp()+interval '1 day')`;
  const principal={ownerId:f.ownerId,agentId:f.agentId,connectionId};
  const actor={ownerId:f.ownerId,agentId:f.agentId,grantId:connectionId,credentialId:connectionId,resource,role:'agent',accessGeneration:1,accessRevision:1,policyRevision:1,permissions:{training:true,ranked:false,forumMessages:false,customTopics:false}};
  const service={db:diagnostics.db,reportClosureState:closure};
  const registered=await registerDiagnosticCase(service,principal,{diagnosticSessionId:randomUUID()});
  const ingress=registerDiagnosticIngress(app,service,{actionDb:main.db,authorizationDb:main.db});
  app.post('/api/agent/mcp',async(request,reply)=>{
   // Actual authoritative SQL before the trusted-principal seam; diagnostics
   // must not consume these business-pool connections while waiting on its lock.
   const grants=await main.client`SELECT id FROM oid_agent_access_grant WHERE id=${connectionId} AND owner_id=${f.ownerId} AND agent_id=${f.agentId} AND revoked_at IS NULL AND expires_at>clock_timestamp()`;
   assert.equal(grants.length,1);await ingress.authenticated(request,principal);
   const handler=createMcpHandler(()=>{
    const sdk=new McpServer({name:'Diagnostic pool isolation',version:'1.0.0'},{supportedProtocolVersions:['2025-06-18']});
    const configuration={inputSchema:z.object({runId:z.string().uuid(),taskIndex:z.number().int(),operationId:z.string(),command:z.object({kind:z.literal('inspect_catalog')})})};
    ingress.toolRegistered(request,'runs.task_action',configuration);
    sdk.registerTool('runs.task_action',configuration,async args=>{ingress.handlerEntered(request);const admitted=await ingress.run(request,()=>admitTaskAction({db:main.db},actor,args));return {content:[{type:'text',text:JSON.stringify(admitted)}],structuredContent:admitted};});return sdk;
   },{legacy:'stateless',responseMode:'json',keepAliveMs:0});
   try{const response=await handler.fetch(new Request(resource,{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify(request.body)}),{parsedBody:request.body});response.headers.forEach((value,key)=>reply.header(key,value));return reply.code(response.status).send(Buffer.from(await response.arrayBuffer()));}finally{await handler.close();}
  });
  const address=await app.listen({host:'127.0.0.1',port:0});
  const sessions=await Promise.all([diagnostics.client.reserve(),diagnostics.client.reserve()]);
  try{const observed=await Promise.all(sessions.map(c=>c`SELECT pg_backend_pid() AS pid,current_setting('statement_timeout') AS statement,current_setting('lock_timeout') AS lock,current_setting('application_name') AS application`));assert.notEqual(observed[0]![0]!.pid,observed[1]![0]!.pid);for(const rows of observed){assert.equal(rows[0]!.statement,'1s');assert.equal(rows[0]!.lock,'500ms');assert.equal(rows[0]!.application,'w3bench-diagnostics');}const mainPid=(await main.client`SELECT pg_backend_pid() AS pid`)[0]!.pid;assert(!observed.some(rows=>rows[0]!.pid===mainPid));}finally{sessions.forEach(c=>c.release());}
  lock=await locker.reserve();await lock`SELECT pg_advisory_lock(hashtext('mcp-diagnostics-global'),0)`;lockHeld=true;
  const writes=Array.from({length:128},()=>captureDiagnosticWork(async()=>{const at=new Date().toISOString();return (await recordServerDiagnostic(service,{event:{eventId:randomUUID(),source:'server',stage:'ingress',tool:'unknown',outcome:'unknown',startedAt:at,completedAt:at,durationMs:0}})).recorded;}));
  for(let i=0;i<20;i++){const waiting=await observer`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=${name} AND application_name='w3bench-diagnostics' AND wait_event_type='Lock'`;if(Number(waiting[0]!.n)>=2)break;await delay(10);}
  assert.equal(Number((await observer`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=${name} AND application_name='w3bench-diagnostics' AND wait_event_type='Lock'`)[0]!.n),2,'actual diagnostic SQL must be waiting on the held advisory lock');
  const ledgerBefore=JSON.stringify(await observer`SELECT id,amount_units::text,entry_type FROM oid_ledger_entry ORDER BY id`);
  const input={runId:f.runId,taskIndex:0,operationId:'isolation_free_inspect_catalog',command:{kind:'inspect_catalog'}};
  const start=performance.now();businessWork=(async()=>{
   const [response,completed]=await Promise.all([
    fetch(address+'/api/agent/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','x-w3bench-diagnostic-case':registered.caseId,'mcp-protocol-version':'2025-06-18'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'runs.task_action',arguments:input}})}),
    completeKnownTrainingRun({db:main.db,taskReleaseSource:{async getActiveAdmissionRelease(){return null;},async getValidatedReleaseRecord(){return completion.record as never;}},evidenceSource:{async load(){return structuredClone(completion.evaluationInput);}}},{runId:completion.runId})]);
   assert.equal(response.status,200);assert.equal(response.headers.get('x-w3bench-diagnostic-capture'),'unavailable');const wire=decodeDiagnosticWire(await response.text(),response.headers.get('content-type')??'');const message=wire?.messages.find(m=>m.id===1) as {result?:{structuredContent?:{admitted?:boolean;actionId?:string}}}|undefined;assert.equal(message?.result?.structuredContent?.admitted,true);assert.equal(completed.status,'completed');return message!.result!.structuredContent!;
  })();
  let timer:ReturnType<typeof setTimeout>|undefined;try{await Promise.race([businessWork,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('business pool starved behind diagnostic lock')),1000);})]);}finally{if(timer)clearTimeout(timer);}
  assert(performance.now()-start<1000,'actual MCP admission and completion must progress within 1s while diagnostic lock remains held');
  const replay=await admitTaskAction({db:main.db},actor,input);assert.equal(replay.admitted,true);
  assert.equal(Number((await observer`SELECT count(*)::int AS n FROM oid_run_task_action WHERE run_id=${f.runId}`)[0]!.n),1);
  assert.equal(Number((await observer`SELECT count(*)::int AS n FROM oid_run_event WHERE run_id=${completion.runId} AND event_type='run.completed'`)[0]!.n),1);
  assert.equal(JSON.stringify(await observer`SELECT id,amount_units::text,entry_type FROM oid_ledger_entry ORDER BY id`),ledgerBefore,'free inspection and diagnostic backlog cannot charge or duplicate ledger entries');
  assert((await Promise.all(writes)).every(value=>value==='unavailable'));
  // Negative control reproduces the old shared-pool design with real service
  // transactions, rather than a fake hung promise: all ten main slots now wait.
  oldSharedWrites=Array.from({length:10},async()=>{const at=new Date().toISOString();return recordServerDiagnostic({db:main.db,reportClosureState:closure},{event:{eventId:randomUUID(),source:'server',stage:'ingress',tool:'unknown',outcome:'unknown',startedAt:at,completedAt:at,durationMs:0}});});
  let oldWaiting=0;for(let i=0;i<40;i++){oldWaiting=Number((await observer`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname=${name} AND application_name<>'w3bench-diagnostics' AND wait_event_type='Lock' AND query LIKE '%mcp-diagnostics-global%'`)[0]!.n);if(oldWaiting===10)break;await delay(10);}assert.equal(oldWaiting,10,'negative control must occupy all old shared main-pool slots');
  let oldProgressed=false;oldQueuedProbe=main.client`SELECT 1 AS business_progress`.then(()=>{oldProgressed=true;});await delay(100);assert.equal(oldProgressed,false,'old shared-pool diagnostic writes must reproduce actual business starvation');
 }finally{
  if(lockHeld&&lock)await lock`SELECT pg_advisory_unlock(hashtext('mcp-diagnostics-global'),0)`.catch(()=>{});lock?.release();setDiagnosticActionSink(main.db,undefined);
  await businessWork?.catch(()=>{});await Promise.allSettled(oldSharedWrites);await oldQueuedProbe?.catch(()=>{});await app.close();await Promise.all([main.client.end({timeout:5}),diagnostics.client.end({timeout:5}),observer.end({timeout:5}),locker.end({timeout:5})]);
  if(created)await admin.unsafe('DROP DATABASE '+name+' WITH (FORCE)');await admin.end({timeout:5});
 }
});
